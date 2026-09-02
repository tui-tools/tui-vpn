package main

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-vpn/internal/wireguard"
)

// enter submits the open dialog without typing anything, which is how a
// prefilled input is accepted and how a picker takes its highlighted option.
func enter(t *testing.T, a *app) *app {
	t.Helper()
	model, _ := a.Update(tea.KeyMsg{Type: tea.KeyEnter})
	return model.(*app)
}

// clearAndType replaces the open input's whole value. The forms prefill from
// the current configuration, so a test that wants a different answer has to
// take the old one out first.
func clearAndType(t *testing.T, a *app, text string) *app {
	t.Helper()
	if a.mode != modeInput {
		t.Fatalf("no input is open (mode %d)", a.mode)
	}
	a.input.Model.SetValue("")
	model, _ := a.Update(key(text))
	a = model.(*app)
	return enter(t, a)
}

// runPending feeds a background command's message back into the model the way
// the tea runtime would, following a batch when there is one.
func runPending(t *testing.T, a *app, cmd tea.Cmd) *app {
	t.Helper()
	if cmd == nil {
		t.Fatal("expected a background command")
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, c := range batch {
			model, _ := a.Update(c())
			a = model.(*app)
		}
		return a
	}
	model, _ := a.Update(msg)
	return model.(*app)
}

// TestServerSettingsFlow drives `S` end to end: two inputs, a diff that shows
// only the changed lines, and the restart behind it.
func TestServerSettingsFlow(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenUsers)

	model, _ := a.Update(key("S"))
	a = model.(*app)
	if a.mode != modeInput {
		t.Fatalf("S did not open the server-settings form (mode %d)", a.mode)
	}
	a = clearAndType(t, a, "https://vpn.example.org")
	a = clearAndType(t, a, "127.0.0.1:8080")

	if a.mode != modeConfirm {
		t.Fatalf("the form did not reach a confirm (mode %d)", a.mode)
	}
	if !strings.Contains(a.confirm.Command, wireguard.HeadscaleConfigPath) {
		t.Errorf("preview = %q, want the config write", a.confirm.Command)
	}
	// The diff is the reason this dialog is trustworthy: exactly two lines
	// out, two lines in.
	body := a.confirm.Body
	if strings.Count(body, "\n- ") != 2 || strings.Count(body, "\n+ ") != 2 {
		t.Errorf("the diff is not the two changed lines:\n%s", body)
	}
	for _, want := range []string{
		`+ server_url: "https://vpn.example.org"`,
		`+ listen_addr: "127.0.0.1:8080"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the diff is missing %q:\n%s", want, body)
		}
	}
	// Nothing the edit did not touch may appear in the dialog.
	if strings.Contains(body, "metrics_listen_addr") || strings.Contains(body, "log:") {
		t.Errorf("the diff shows lines the edit does not change:\n%s", body)
	}

	a = confirmAndRun(t, a)

	if a.mode != modeConfirm {
		t.Fatalf("the write did not chain the restart (mode %d)", a.mode)
	}
	if !strings.Contains(a.confirm.Command, "systemctl restart headscale") {
		t.Errorf("preview = %q, want the restart", a.confirm.Command)
	}
	a = confirmAndRun(t, a)

	state, err := a.backend.Load(t.Context())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := state.Headscale.ControlPlane.ServerURL; got != "https://vpn.example.org" {
		t.Errorf("server_url after the flow = %q", got)
	}
	// The rest of the demo's configuration survived the round trip.
	if !strings.Contains(state.Headscale.ControlPlane.Raw, "metrics_listen_addr: 127.0.0.1:9090") {
		t.Error("the write lost a key it was not asked to change")
	}
}

// TestServerSettingsWarnsAboutAnUnreachableURL: a syntactically fine URL that
// no client's browser can reach is the failure this form exists to prevent.
func TestServerSettingsWarnsAboutAnUnreachableURL(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenUsers)
	model, _ := a.Update(key("S"))
	a = model.(*app)
	a = clearAndType(t, a, "http://127.0.0.1:8080")
	a = enter(t, a) // keep the prefilled listen_addr

	if a.mode != modeConfirm {
		t.Fatalf("mode = %d, want a confirm", a.mode)
	}
	if !strings.Contains(a.confirm.Body, "WARNING") {
		t.Errorf("a plain-http loopback server_url was not warned about:\n%s", a.confirm.Body)
	}
}

// TestOIDCFlowNeverShowsTheSecret is the test the whole feature is written
// around. It drives the form with a real secret and asserts the value appears
// in exactly one place — the stdin of the command that writes it to a
// root-only file — and nowhere a human or a log could see it.
func TestOIDCFlowNeverShowsTheSecret(t *testing.T) {
	const secret = "totally-secret-value-42"

	a := newTestApp(t)
	a.setScreen(wireguard.ScreenUsers)

	model, _ := a.Update(key("O"))
	a = model.(*app)
	if a.mode != modeInput {
		t.Fatalf("O did not open the OIDC form (mode %d)", a.mode)
	}

	a = clearAndType(t, a, "https://idp.example.org/realms/prod") // issuer
	a = clearAndType(t, a, "headscale-prod")                      // client id
	a = clearAndType(t, a, secret)                                // client secret, masked
	a = clearAndType(t, a, "example.org, partner.example")        // allowed domains
	a = clearAndType(t, a, "vpn-users")                           // allowed groups

	// Allowed users: an empty answer is "none", not a cancellation.
	a.input.Model.SetValue("")
	a = enter(t, a)
	if a.mode != modeInput {
		t.Fatalf("an empty allow list cancelled the form (mode %d)", a.mode)
	}
	a = enter(t, a) // scope, prefilled

	// The two switches are pickers.
	if a.mode != modePicker {
		t.Fatalf("mode = %d, want the only_start picker", a.mode)
	}
	a = enter(t, a)
	if a.mode != modePicker {
		t.Fatalf("mode = %d, want the pkce picker", a.mode)
	}
	model, cmd := a.Update(tea.KeyMsg{Type: tea.KeyEnter})
	a = model.(*app)

	// The pkce answer kicks off the issuer discovery, which is a background
	// read against the demo IdP.
	a = runPending(t, a, cmd)
	if a.mode != modeConfirm {
		t.Fatalf("discovery did not open the secret confirm (mode %d)", a.mode)
	}

	// Step 1: the secret file. The dialog names the path and never the value.
	if !strings.Contains(a.confirm.Command, wireguard.OIDCClientSecretPath) {
		t.Errorf("preview = %q, want the secret write", a.confirm.Command)
	}
	assertNoSecret(t, a, secret, "the secret-write dialog")
	a = confirmAndRun(t, a)

	// Step 2: config.yaml. The diff must carry client_secret_path and not a
	// client_secret.
	if a.mode != modeConfirm {
		t.Fatalf("the secret write did not chain the config write (mode %d)", a.mode)
	}
	body := a.confirm.Body
	if !strings.Contains(body, "client_secret_path") {
		t.Errorf("the diff does not point headscale at the secret file:\n%s", body)
	}
	if strings.Contains(body, "\n+   client_secret:") {
		t.Errorf("the diff writes a client_secret into config.yaml:\n%s", body)
	}
	assertNoSecret(t, a, secret, "the config-write dialog")
	a = confirmAndRun(t, a)

	// Step 3: the restart.
	if !strings.Contains(a.confirm.Command, "systemctl restart headscale") {
		t.Fatalf("preview = %q, want the restart", a.confirm.Command)
	}
	a = confirmAndRun(t, a)

	// The secret is out of the model entirely.
	if a.cpDraft.clientSecret != "" {
		t.Error("the draft is still holding the secret after the flow")
	}

	state, err := a.backend.Load(t.Context())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cp := state.Headscale.ControlPlane
	if cp.OIDC.Issuer != "https://idp.example.org/realms/prod" {
		t.Errorf("issuer = %q", cp.OIDC.Issuer)
	}
	if cp.OIDC.ClientID != "headscale-prod" {
		t.Errorf("client_id = %q", cp.OIDC.ClientID)
	}
	if strings.Join(cp.OIDC.AllowedDomains, " ") != "example.org partner.example" {
		t.Errorf("allowed_domains = %v", cp.OIDC.AllowedDomains)
	}
	if len(cp.OIDC.AllowedUsers) != 0 {
		t.Errorf("allowed_users = %v, want none", cp.OIDC.AllowedUsers)
	}
	// The written file must not carry the value anywhere.
	if strings.Contains(cp.Raw, secret) {
		t.Fatal("the secret was written into config.yaml")
	}
	// Every command that ran, and every preview of one.
	fake, ok := a.backend.(*wireguard.Fake)
	if !ok {
		t.Fatal("the test backend is not the fake")
	}
	for _, cmd := range fake.Commands() {
		if strings.Contains(cmd.String(), secret) ||
			strings.Contains(cmd.Description, secret) {
			t.Fatalf("the secret is on a command line: %q", cmd.String())
		}
	}
}

// assertNoSecret checks that a value appears nowhere a person could read it.
func assertNoSecret(t *testing.T, a *app, secret, where string) {
	t.Helper()
	for label, text := range map[string]string{
		"body": a.confirm.Body, "command": a.confirm.Command,
		"title": a.confirm.Title, "status": a.status,
		"view": a.View(),
	} {
		if strings.Contains(text, secret) {
			t.Fatalf("%s leaks the secret in its %s", where, label)
		}
	}
}

// TestOIDCFlowKeepsAnExistingSecret: leaving the secret empty when one is
// already configured must skip the secret write, not fail and not blank it.
func TestOIDCFlowKeepsAnExistingSecret(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenUsers)
	if !a.state.Headscale.ControlPlane.OIDC.ClientSecretSet {
		t.Fatal("the demo configuration should already have a secret set")
	}

	model, _ := a.Update(key("O"))
	a = model.(*app)
	a = enter(t, a)                                        // issuer, prefilled
	a = enter(t, a)                                        // client id, prefilled
	a = enter(t, a)                                        // client secret, left empty
	a = clearAndType(t, a, "example.com, new.example")     // allowed domains
	a = enter(t, a)                                        // groups
	a = enter(t, a)                                        // users
	a = enter(t, a)                                        // scope
	a = enter(t, a)                                        // only_start
	model, cmd := a.Update(tea.KeyMsg{Type: tea.KeyEnter}) // pkce
	a = model.(*app)
	a = runPending(t, a, cmd)

	if a.mode != modeConfirm {
		t.Fatalf("mode = %d, want a confirm", a.mode)
	}
	// The first confirm is the config write: no secret was typed, so there is
	// no secret file to write.
	if strings.Contains(a.confirm.Command, wireguard.OIDCClientSecretPath) {
		t.Errorf("an unchanged secret still opened a secret write: %q", a.confirm.Command)
	}
	if !strings.Contains(a.confirm.Command, wireguard.HeadscaleConfigPath) {
		t.Errorf("preview = %q, want the config write", a.confirm.Command)
	}
	if !strings.Contains(a.confirm.Body, "allowed_domains") {
		t.Errorf("the diff does not show the changed allow list:\n%s", a.confirm.Body)
	}
}

// TestOIDCFlowSavesDespiteADeadIdP: discovery is a check, not a gate. A
// warning must be shown, and saving must still be possible — an IdP that is
// down right now is not a reason to be unable to write down its address.
func TestOIDCFlowSavesDespiteADeadIdP(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenUsers)
	a.cpDraft = controlPlaneDraft{
		issuer:    "https://idp.example.net/realms/down",
		clientID:  "headscale",
		scope:     []string{"openid", "profile", "email"},
		onlyStart: true,
	}
	model, _ := a.Update(discoveredMsg{ok: false, detail: "curl: (28) connection timed out"})
	a = model.(*app)

	if a.mode != modeConfirm {
		t.Fatalf("a failed discovery blocked the save (mode %d)", a.mode)
	}
	if !strings.Contains(a.confirm.Body, "WARNING") ||
		!strings.Contains(a.confirm.Body, "connection timed out") {
		t.Errorf("the failure was not reported in the dialog:\n%s", a.confirm.Body)
	}
}

// TestCancellingTheOIDCFormForgetsTheSecret: an abandoned form must not leave a
// typed credential sitting in the process.
func TestCancellingTheOIDCFormForgetsTheSecret(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenUsers)
	model, _ := a.Update(key("O"))
	a = model.(*app)
	a = enter(t, a) // issuer
	a = enter(t, a) // client id
	a = clearAndType(t, a, "a-secret-that-must-not-linger")
	if a.cpDraft.clientSecret == "" {
		t.Fatal("the secret was not collected in the first place")
	}
	model, _ = a.Update(tea.KeyMsg{Type: tea.KeyEsc})
	a = model.(*app)
	if a.cpDraft.clientSecret != "" {
		t.Error("cancelling the form kept the typed secret")
	}
}

// TestControlPlanePanelShowsTheConfiguration: the users screen has to answer
// what it used to only assert. The panel names the server URL and the issuer,
// and says a secret is set without being able to say what it is.
func TestControlPlanePanelShowsTheConfiguration(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenUsers)
	view := a.View()
	for _, want := range []string{
		"control plane",
		"https://vpn.example.com",
		"https://idp.example.com/realms/demo",
		"secret set",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("the users screen does not show %q:\n%s", want, view)
		}
	}
	// The other control-plane screens keep the one-line note, not the panel.
	a.setScreen(wireguard.ScreenNodes)
	if strings.Contains(a.View(), "control plane · ") {
		t.Error("the panel should be on the users screen only")
	}
}

// TestConfigWriteIsRefusedWhenUnreadable: editing a file that could not be read
// would mean writing a guess over somebody's configuration.
func TestConfigWriteIsRefusedWhenUnreadable(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenUsers)
	a.state.Headscale.ControlPlane = wireguard.ControlPlane{
		ConfigPath: wireguard.HeadscaleConfigPath,
		Error:      "permission denied",
	}
	for _, k := range []string{"S", "O"} {
		model, _ := a.Update(key(k))
		a = model.(*app)
		if a.mode != modeBrowse {
			t.Fatalf("%s opened a form against an unreadable configuration", k)
		}
		if !strings.Contains(a.status, "permission denied") {
			t.Errorf("%s: status = %q, want the reason", k, a.status)
		}
	}
}
