package main

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/theme"
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

// TestServerSettingsFlow drives `S` end to end on the demo, which sits behind
// a reverse proxy: the transport is kept, a new server_url typed, listen_addr
// and base_domain accepted as they are — and the diff is the one line that
// changed, followed by the enable and restart the running, disabled unit
// needs.
func TestServerSettingsFlow(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenUsers)

	model, _ := a.Update(key("S"))
	a = model.(*app)
	if a.mode != modePicker || a.pickerPurpose != pickerTransport {
		t.Fatalf("S did not open the transport choice (mode %d)", a.mode)
	}
	if a.picker.Selected() != transportOptions[wireguard.TransportReverseProxy] {
		t.Errorf("the picker is not on the current transport: %q", a.picker.Selected())
	}
	a = enter(t, a)
	a = clearAndType(t, a, "https://vpn.example.org")
	if a.input.Model.Value() != "127.0.0.1:8080" {
		t.Errorf("listen_addr prefill = %q, want the loopback bind a proxy needs",
			a.input.Model.Value())
	}
	a = enter(t, a)
	if a.inputPurpose != inputBaseDomain || a.input.Model.Value() != "tailnet.example.net" {
		t.Fatalf("no base_domain step (purpose %d, value %q)", a.inputPurpose,
			a.input.Model.Value())
	}
	a = enter(t, a)

	if a.mode != modeConfirm {
		t.Fatalf("the form did not reach a confirm (mode %d, status %q)", a.mode, a.status)
	}
	if !strings.Contains(a.confirm.Command, wireguard.HeadscaleConfigPath) {
		t.Errorf("preview = %q, want the config write", a.confirm.Command)
	}
	// The diff is the reason this dialog is trustworthy: one line out, one in.
	body := a.confirm.Body
	if strings.Count(body, "\n- ") != 1 || strings.Count(body, "\n+ ") != 1 {
		t.Errorf("the diff is not the one changed line:\n%s", body)
	}
	if !strings.Contains(body, `+ server_url: "https://vpn.example.org"`) {
		t.Errorf("the diff is missing the new server_url:\n%s", body)
	}
	if !strings.Contains(body, "Transport: reverse proxy") {
		t.Errorf("the dialog does not name the transport:\n%s", body)
	}
	a = confirmAndRun(t, a)

	// The demo's unit is running but disabled, so the tail is an enable and
	// then the restart that reads the new configuration.
	if a.mode != modeConfirm {
		t.Fatalf("the write did not chain the enable (mode %d)", a.mode)
	}
	if a.confirm.Command != "systemctl enable headscale" {
		t.Errorf("preview = %q, want the enable", a.confirm.Command)
	}
	a = confirmAndRun(t, a)
	if a.mode != modeConfirm {
		t.Fatalf("the enable did not chain the restart (mode %d)", a.mode)
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

// walkServerSettings drives S on the demo keeping every answer but the
// server_url, up to the config-write confirm.
func walkServerSettings(t *testing.T, a *app, serverURL string) *app {
	t.Helper()
	a.setScreen(wireguard.ScreenUsers)
	model, _ := a.Update(key("S"))
	a = model.(*app)
	a = enter(t, a)                   // the current transport
	a = clearAndType(t, a, serverURL) // server_url
	a = enter(t, a)                   // listen_addr
	return enter(t, a)                // base_domain
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
	// The provider picker opens on the demo's own, a generic OIDC issuer.
	a = pick(t, a, wireguard.ProviderGeneric.Label)
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
	// The demo's unit runs headscale as its own user, so the previewed write
	// has to hand the file to that account: a root-only secret is one the
	// service cannot read after the restart two steps later.
	if !strings.Contains(a.confirm.Command, "-o headscale -g headscale") {
		t.Errorf("preview = %q, want the file owned by the service account",
			a.confirm.Command)
	}
	if !strings.Contains(a.confirm.Command, "-m 600") {
		t.Errorf("preview = %q, want mode 600", a.confirm.Command)
	}
	if !strings.Contains(a.confirm.Body, "headscale:headscale") {
		t.Errorf("the dialog does not say who will own the file:\n%s", a.confirm.Body)
	}
	assertNoSecret(t, a, secret, "the secret-write dialog")
	a = confirmAndRun(t, a)

	// Step 2: config.yaml. The diff must not carry a client_secret.
	if a.mode != modeConfirm {
		t.Fatalf("the secret write did not chain the config write (mode %d)", a.mode)
	}
	// The demo already points client_secret_path at the file, so that line
	// is not in the diff: an unchanged value is not a change, however the
	// editor would have quoted it.
	body := a.confirm.Body
	if strings.Contains(body, "client_secret_path") {
		t.Errorf("the diff rewrites a client_secret_path that already says this:\n%s", body)
	}
	if strings.Contains(body, "\n+   client_secret:") {
		t.Errorf("the diff writes a client_secret into config.yaml:\n%s", body)
	}
	assertNoSecret(t, a, secret, "the config-write dialog")
	a = confirmAndRun(t, a)

	// Step 3: the demo's unit is disabled, so it is enabled first, and
	// step 4 is the restart.
	if a.confirm.Command != "systemctl enable headscale" {
		t.Fatalf("preview = %q, want the enable", a.confirm.Command)
	}
	a = confirmAndRun(t, a)
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
	if cp.OIDC.ClientSecretPath != wireguard.OIDCClientSecretPath {
		t.Errorf("client_secret_path = %q, want the secret file", cp.OIDC.ClientSecretPath)
	}
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
	a = enter(t, a)                                        // provider, preselected
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
	a = enter(t, a) // provider
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

// TestPanelNamesTheServiceAccount: the account is on screen because it is what
// the secret file will be owned by, so a wrong one is visible before the write.
func TestPanelNamesTheServiceAccount(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenUsers)
	if !strings.Contains(a.View(), "runs as headscale:headscale") {
		t.Errorf("the panel does not name the service account:\n%s", a.View())
	}
}

// TestRestartStepFollowsTheUnitState: the last step of S depends on whether
// the unit starts at boot. A fresh install (inactive, disabled) is enabled and
// started in one command; an enabled unit gets the plain restart it always
// got; and a disabled unit that is already running is enabled and then
// restarted, because `enable --now` would leave it on the old configuration.
func TestRestartStepFollowsTheUnitState(t *testing.T) {
	for _, tc := range []struct {
		name, active, enabled string
		want                  []string
	}{
		{"fresh install", "inactive", "disabled",
			[]string{"systemctl enable --now headscale"}},
		{"already enabled", "active", "enabled",
			[]string{"systemctl restart headscale"}},
		{"running but disabled", "active", "disabled",
			[]string{"systemctl enable headscale", "systemctl restart headscale"}},
		{"state unknown", "unknown", "unknown",
			[]string{"systemctl restart headscale"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := wireguard.NewFake()
			fake.SetService(tc.active, tc.enabled)
			a := newApp(fake, theme.New(), nil)
			a.width, a.height = 100, 30
			state, err := fake.Load(t.Context())
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			a.state, a.loading = state, false
			a = walkServerSettings(t, a, "https://vpn.example.org")
			a = confirmAndRun(t, a) // the config write

			for i, want := range tc.want {
				if a.mode != modeConfirm {
					t.Fatalf("step %d: no confirm open (mode %d)", i, a.mode)
				}
				if a.confirm.Command != want {
					t.Fatalf("step %d: preview = %q, want %q", i, a.confirm.Command, want)
				}
				a = confirmAndRun(t, a)
			}
			if a.mode == modeConfirm {
				t.Fatalf("an extra step followed: %q", a.confirm.Command)
			}
			after, _ := fake.Load(t.Context())
			if tc.enabled == "disabled" && after.Headscale.ControlPlane.ServiceEnabled != "enabled" {
				t.Errorf("the unit is still %q after the flow",
					after.Headscale.ControlPlane.ServiceEnabled)
			}
		})
	}
}

// TestPanelSaysWhetherTheUnitStartsAtBoot: enabled or disabled sits next to
// the active state, and a disabled unit says what that costs.
func TestPanelSaysWhetherTheUnitStartsAtBoot(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenUsers)
	view := a.View()
	if !strings.Contains(view, "headscale active · disabled") {
		t.Errorf("the panel does not show the enabled state:\n%s", view)
	}
	if !strings.Contains(view, "won't start at boot") {
		t.Errorf("a disabled unit is not called out:\n%s", view)
	}
}

// TestFixOwnershipFlow drives F on the demo, whose noise key is root's: the
// panel names the file, F previews one recursive chown of the state
// directory, and the restart tail follows it.
func TestFixOwnershipFlow(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenUsers)
	view := a.View()
	if !strings.Contains(view, "/var/lib/headscale/noise_private.key is root:root") {
		t.Errorf("the panel does not name the mismatch:\n%s", view)
	}

	model, _ := a.Update(key("F"))
	a = model.(*app)
	if a.mode != modeConfirm {
		t.Fatalf("F did not open a confirm (mode %d)", a.mode)
	}
	if a.confirm.Command != "chown -R headscale:headscale /var/lib/headscale" {
		t.Errorf("preview = %q", a.confirm.Command)
	}
	if !strings.Contains(a.confirm.Body, "root:root → headscale:headscale") {
		t.Errorf("the dialog does not say what it fixes:\n%s", a.confirm.Body)
	}
	a = confirmAndRun(t, a)

	// The restart tail: the demo unit is running but disabled.
	if a.mode != modeConfirm || a.confirm.Command != "systemctl enable headscale" {
		t.Fatalf("the fix did not chain the enable: mode %d, %q", a.mode, a.confirm.Command)
	}
	model, _ = a.Update(tea.KeyMsg{Type: tea.KeyEsc})
	a = model.(*app)

	state, _ := a.backend.Load(t.Context())
	a.state = state
	if !state.Headscale.ControlPlane.Ownership.OK() {
		t.Errorf("ownership after the fix = %+v", state.Headscale.ControlPlane.Ownership)
	}
	if !strings.Contains(a.View(), "owned as expected") {
		t.Errorf("the panel does not say the ownership is fine now:\n%s", a.View())
	}

	// F with nothing to fix says so and opens nothing.
	model, _ = a.Update(key("F"))
	a = model.(*app)
	if a.mode != modeBrowse || !strings.Contains(a.status, "nothing to fix") {
		t.Errorf("F on a clean host: mode %d, status %q", a.mode, a.status)
	}
}

// TestFixOwnershipChainsEveryFile: the secret and the backup get their own
// non-recursive chowns after the state directory's, one confirm each.
func TestFixOwnershipChainsEveryFile(t *testing.T) {
	fake := wireguard.NewFake()
	fake.SetStat(wireguard.FileStat{Path: wireguard.OIDCClientSecretPath,
		User: "root", Group: "root", Mode: 0o600})
	fake.SetService("active", "enabled")
	a := newApp(fake, theme.New(), nil)
	a.width, a.height = 100, 30
	a.state, _ = fake.Load(t.Context())
	a.loading = false
	a.setScreen(wireguard.ScreenUsers)

	model, _ := a.Update(key("F"))
	a = model.(*app)
	for i, want := range []string{
		"chown headscale:headscale " + wireguard.OIDCClientSecretPath,
		"chown -R headscale:headscale /var/lib/headscale",
		"systemctl restart headscale",
	} {
		if a.mode != modeConfirm || a.confirm.Command != want {
			t.Fatalf("step %d: mode %d, preview %q, want %q", i, a.mode, a.confirm.Command, want)
		}
		a = confirmAndRun(t, a)
	}
}

// TestFixOwnershipNeedsACheck: an ownership that could not be read is not a
// clean one, and F says why it has nothing to offer.
func TestFixOwnershipNeedsACheck(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenUsers)
	a.state.Headscale.ControlPlane.Ownership = wireguard.Ownership{}
	model, _ := a.Update(key("F"))
	a = model.(*app)
	if a.mode != modeBrowse || !strings.Contains(a.status, "not checked") {
		t.Errorf("mode %d, status %q", a.mode, a.status)
	}
	if strings.Contains(a.View(), "ownership   ") {
		t.Error("the panel reports an ownership it never checked")
	}
}

// TestListScreensWithTheUnitStopped is the real case: a fresh package, the
// unit inactive, and the users, nodes and keys screens used to show the CLI's
// truncated socket error. They now say the unit is not running and point at S,
// and creating a user says so instead of running a command that cannot work.
func TestListScreensWithTheUnitStopped(t *testing.T) {
	a, fake := fixtureApp(t, "headscale-config.yaml")
	fake.SetService("inactive", "disabled")
	state, _ := fake.Load(t.Context())
	a.state = state
	for _, screen := range []wireguard.Screen{wireguard.ScreenUsers, wireguard.ScreenNodes,
		wireguard.ScreenKeys} {
		a.setScreen(screen)
		view := a.View()
		if !strings.Contains(view, "headscale is not running · S configures and starts it") {
			t.Errorf("screen %d does not say the unit is stopped:\n%s", screen, view)
		}
		if strings.Contains(view, "could not read Headscale") {
			t.Errorf("screen %d still reports a read failure", screen)
		}
	}
	a.setScreen(wireguard.ScreenUsers)
	model, _ := a.Update(key("n"))
	a = model.(*app)
	if a.mode != modeBrowse || !strings.Contains(a.status, "not running") {
		t.Errorf("n on a stopped unit: mode %d, status %q", a.mode, a.status)
	}

	// S still works, and on a stopped, disabled unit its tail is the one
	// enable --now: two steps in all.
	a = startS(t, a, wireguard.TransportPlainHTTP)
	a = clearAndType(t, a, "http://203.0.113.10:443")
	a = enter(t, a)
	a = clearAndType(t, a, "tailnet.internal")
	if !strings.Contains(a.confirm.Body, "Step 1 of 2") {
		t.Errorf("the count is not 1 of 2 for write + enable --now:\n%s", a.confirm.Body)
	}
}

// TestStepCountWithEnableAndRestart: a running but disabled unit ends the flow
// with an enable and a restart, so the write is step 1 of 3.
func TestStepCountWithEnableAndRestart(t *testing.T) {
	a := newTestApp(t) // the demo unit is active and disabled
	a.setScreen(wireguard.ScreenUsers)
	model, _ := a.Update(key("S"))
	a = model.(*app)
	a = enter(t, a)
	a = clearAndType(t, a, "https://vpn.example.org")
	a = enter(t, a)
	a = enter(t, a)
	if !strings.Contains(a.confirm.Body, "Step 1 of 3") {
		t.Errorf("the count is not 1 of 3 for write + enable + restart:\n%s", a.confirm.Body)
	}
}
