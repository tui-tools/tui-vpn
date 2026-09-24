package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-vpn/internal/wireguard"
)

// googleGroupsConfig is the demo configuration as the real host had it:
// federated to Google, with an allowed_groups entry kept from a placeholder.
func googleGroupsConfig(t *testing.T, fake *wireguard.Fake) {
	t.Helper()
	state, _ := fake.Load(t.Context())
	raw := state.Headscale.ControlPlane.Raw
	for old, repl := range map[string]string{
		"issuer: https://idp.example.com/realms/demo": "issuer: https://accounts.google.com",
		"allowed_groups: []":                          `allowed_groups: ["vpn-users"]`,
	} {
		if !strings.Contains(raw, old) {
			t.Fatalf("the demo configuration has no %q", old)
		}
		raw = strings.Replace(raw, old, repl, 1)
	}
	fake.SetConfig(raw)
}

// TestGooglePreset drives O with the Google preset: the issuer and the scope
// are filled in, the groups step is skipped and the list emptied, the dialog
// shows the redirect URI to register and says the lists are combined with
// AND, and a listed user outside allowed_domains is warned about.
func TestGooglePreset(t *testing.T) {
	a, fake := fixtureApp(t, "")
	googleGroupsConfig(t, fake)
	a.state, _ = fake.Load(t.Context())

	// The panel flags the groups list Google can never satisfy.
	if view := a.View(); !strings.Contains(view, "sends no groups claim") {
		t.Errorf("the panel does not flag allowed_groups with Google:\n%s", view)
	}

	model, _ := a.Update(key("O"))
	a = model.(*app)
	if a.pickerPurpose != pickerOIDCProvider ||
		a.picker.Selected() != wireguard.ProviderGoogle.Label {
		t.Fatalf("O did not open the provider picker on Google (purpose %d, %q)",
			a.pickerPurpose, a.picker.Selected())
	}
	a = enter(t, a)
	if a.inputPurpose != inputOIDCClientID {
		t.Fatalf("the Google preset did not skip the issuer (purpose %d)", a.inputPurpose)
	}
	if !strings.Contains(a.input.Help,
		"Register https://vpn.example.com/oidc/callback as the OAuth client's redirect URI") {
		t.Errorf("the client id step does not show the redirect URI:\n%s", a.input.Help)
	}
	a = clearAndType(t, a, "1234-demo.apps.googleusercontent.example")
	a = clearAndType(t, a, "a-google-secret")
	a = clearAndType(t, a, "example.com")
	if a.inputPurpose != inputOIDCUsers {
		t.Fatalf("the Google preset did not skip the groups step (purpose %d)", a.inputPurpose)
	}
	if !strings.Contains(a.input.Help, wireguard.AllowListsRule) {
		t.Errorf("the users step does not state the AND rule:\n%s", a.input.Help)
	}
	a = clearAndType(t, a, "ana@example.com, bo@mail.example.net")
	if !strings.Contains(a.status, "bo@mail.example.net") {
		t.Errorf("no warning for a user outside allowed_domains: %q", a.status)
	}
	if a.mode != modePicker || a.pickerPurpose != pickerOIDCOnlyStart {
		t.Fatalf("the Google preset did not skip the scope step (mode %d, purpose %d)",
			a.mode, a.pickerPurpose)
	}
	a = enter(t, a)
	model, cmd := a.Update(tea.KeyMsg{Type: tea.KeyEnter})
	a = model.(*app)
	a = runPending(t, a, cmd)
	if a.mode != modeConfirm {
		t.Fatalf("no confirm (mode %d, status %q)", a.mode, a.status)
	}
	body := a.confirm.Body
	for _, want := range []string{"Provider: Google", "no groups claim", wireguard.AllowListsRule,
		"Register https://vpn.example.com/oidc/callback", "WARNING: allowed_users bo@mail.example.net"} {
		if !strings.Contains(body, want) {
			t.Errorf("the dialog is missing %q:\n%s", want, body)
		}
	}
	a = confirmAndRun(t, a) // the secret file
	// The issuer and the scope already match the preset in this file, so
	// the diff is the client id, the emptied groups and the users.
	_, added := diffLines(a)
	diff := strings.Join(added, "\n")
	if !strings.Contains(diff, `allowed_groups: []`) {
		t.Errorf("allowed_groups was not cleared:\n%s", a.confirm.Body)
	}
}

// TestGooglePresetRefusesAnHTTPRedirect: Google accepts only https on a DNS
// name, so O says so before asking anything, instead of after the restart.
func TestGooglePresetRefusesAnHTTPRedirect(t *testing.T) {
	a, _ := fixtureApp(t, "headscale-config.yaml") // http://127.0.0.1:8080
	model, _ := a.Update(key("O"))
	a = model.(*app)
	a = pick(t, a, wireguard.ProviderGoogle.Label)
	if a.mode != modeBrowse || !strings.Contains(a.status, "Google refuses") {
		t.Errorf("mode %d, status %q", a.mode, a.status)
	}
}

// TestGenericWithGooglesIssuerSkipsGroups: typing Google's issuer into the
// generic flow gets the Google rules too.
func TestGenericWithGooglesIssuerSkipsGroups(t *testing.T) {
	a, _ := fixtureApp(t, "")
	model, _ := a.Update(key("O"))
	a = model.(*app)
	a = pick(t, a, wireguard.ProviderGeneric.Label)
	a = clearAndType(t, a, "https://accounts.google.com")
	a = clearAndType(t, a, "client")
	a = enter(t, a) // keep the secret
	a = clearAndType(t, a, "example.com")
	if a.inputPurpose != inputOIDCUsers {
		t.Errorf("the groups step was not skipped for Google's issuer (purpose %d)", a.inputPurpose)
	}
}

// TestCheckReportsOIDCReadiness: the readiness block, and the issuer probe
// only when asked for.
func TestCheckReportsOIDCReadiness(t *testing.T) {
	for _, probe := range []bool{false, true} {
		var out strings.Builder
		if err := runCheckWith(context.Background(), wireguard.NewFake(), nil, &out,
			checkOptions{probeIssuer: probe}); err != nil {
			t.Fatal(err)
		}
		var report checkReport
		if err := json.Unmarshal([]byte(out.String()), &report); err != nil {
			t.Fatal(err)
		}
		r := report.Headscale.ControlPlane.OIDCReadiness
		if r == nil || !r.RedirectHTTPS || !r.AllowListsNonEmpty || r.GroupsWithNoGroupsIdP {
			t.Fatalf("readiness = %+v", r)
		}
		if probe != (r.IssuerReachable != nil) || (probe && !*r.IssuerReachable) {
			t.Errorf("probe %v: issuerReachable = %v", probe, r.IssuerReachable)
		}
		if strings.Contains(out.String(), "://") {
			t.Error("--check printed a URL")
		}
	}
}

// TestGooglePresetFillsTheIssuer: from another IdP, the preset writes Google's
// issuer and the default scope without asking for either.
func TestGooglePresetFillsTheIssuer(t *testing.T) {
	a, _ := fixtureApp(t, "")
	model, _ := a.Update(key("O"))
	a = model.(*app)
	a = pick(t, a, wireguard.ProviderGoogle.Label)
	a = clearAndType(t, a, "client")
	a = enter(t, a) // keep the secret
	a = enter(t, a) // domains as they are
	a = enter(t, a) // users as they are
	a = enter(t, a) // only_start
	model, cmd := a.Update(tea.KeyMsg{Type: tea.KeyEnter})
	a = model.(*app)
	a = runPending(t, a, cmd)
	if !strings.Contains(a.confirm.Body, `+   issuer: "https://accounts.google.com"`) {
		t.Errorf("the preset's issuer is not written:\n%s", a.confirm.Body)
	}
}
