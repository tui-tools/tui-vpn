package main

import (
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-vpn/internal/wireguard"
)

// fixtureApp is a test app on the demo backend with config.yaml replaced by
// one of the package's fixtures, and the unit already enabled so the tail of
// every flow is the plain restart.
func fixtureApp(t *testing.T, fixture string) (*app, *wireguard.Fake) {
	t.Helper()
	fake := wireguard.NewFake()
	if fixture != "" {
		data, err := os.ReadFile("../../internal/wireguard/testdata/" + fixture) //nolint:gosec // testdata is in the repository
		if err != nil {
			t.Fatalf("read %s: %v", fixture, err)
		}
		fake.SetConfig(string(data))
	}
	fake.SetService("active", "enabled")
	a := newApp(fake, theme.New(), nil)
	a.width, a.height = 120, 40
	state, err := fake.Load(t.Context())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	a.state, a.loading = state, false
	a.setScreen(wireguard.ScreenUsers)
	return a, fake
}

// pick selects a picker option by its text and submits it.
func pick(t *testing.T, a *app, option string) *app {
	t.Helper()
	if a.mode != modePicker {
		t.Fatalf("no picker is open (mode %d, status %q)", a.mode, a.status)
	}
	for i, o := range a.picker.Options {
		if o == option {
			a.picker.Cursor = i
			return enter(t, a)
		}
	}
	t.Fatalf("the picker has no option %q: %q", option, a.picker.Options)
	return a
}

// startS opens S and picks a transport.
func startS(t *testing.T, a *app, transport wireguard.Transport) *app {
	t.Helper()
	model, _ := a.Update(key("S"))
	a = model.(*app)
	return pick(t, a, transportOptions[transport])
}

// diffLines returns the - and + lines of the confirm dialog's diff.
func diffLines(a *app) (removed, added []string) {
	for _, line := range strings.Split(a.confirm.Body, "\n") {
		switch {
		case strings.HasPrefix(line, "- "):
			removed = append(removed, strings.TrimPrefix(line, "- "))
		case strings.HasPrefix(line, "+ "):
			added = append(added, strings.TrimPrefix(line, "+ "))
		}
	}
	return removed, added
}

// TestPlainHTTPOnAnIP is the case the transport choice exists to make
// painless: the stock configuration, served by IP over plain http on 443,
// with a private MagicDNS domain. listen_addr is proposed from the URL's
// port, no TLS line is written, and the diff is exactly three lines.
func TestPlainHTTPOnAnIP(t *testing.T) {
	a, fake := fixtureApp(t, "headscale-config.yaml")
	if wireguard.DetectTransport(a.state.Headscale.ControlPlane) != wireguard.TransportPlainHTTP {
		t.Fatal("the stock configuration should read as plain http")
	}
	a = startS(t, a, wireguard.TransportPlainHTTP)
	a = clearAndType(t, a, "http://203.0.113.10:443")
	if got := a.input.Model.Value(); got != "0.0.0.0:443" {
		t.Errorf("listen_addr prefill = %q, want the wildcard on the URL's port", got)
	}
	a = enter(t, a)
	a = clearAndType(t, a, "tailnet.internal")

	if a.mode != modeConfirm {
		t.Fatalf("no confirm (mode %d, status %q)", a.mode, a.status)
	}
	removed, added := diffLines(a)
	want := []string{
		`server_url: "http://203.0.113.10:443"`,
		`listen_addr: "0.0.0.0:443"`,
		`  base_domain: "tailnet.internal"`,
	}
	if len(removed) != 3 || strings.Join(added, "\n") != strings.Join(want, "\n") {
		t.Errorf("the diff is not the three lines:\n%s", a.confirm.Body)
	}
	if strings.Contains(a.confirm.Body, "tls_") || strings.Contains(a.confirm.Body, "acme") {
		t.Errorf("plain http wrote a TLS line:\n%s", a.confirm.Body)
	}
	// The explanation replaces the bare warning: plain http is fine here.
	if !strings.Contains(a.confirm.Body, "Noise-encrypted") ||
		strings.Contains(a.confirm.Body, "WARNING") {
		t.Errorf("the dialog does not explain plain http, or still warns:\n%s", a.confirm.Body)
	}
	a = confirmAndRun(t, a)
	if a.confirm.Command != "systemctl restart headscale" {
		t.Errorf("tail = %q", a.confirm.Command)
	}
	a = confirmAndRun(t, a)

	state, _ := fake.Load(t.Context())
	cp := state.Headscale.ControlPlane
	if cp.ServerURL != "http://203.0.113.10:443" || cp.ListenAddr != "0.0.0.0:443" ||
		cp.BaseDomain != "tailnet.internal" {
		t.Errorf("after the flow: %q %q %q", cp.ServerURL, cp.ListenAddr, cp.BaseDomain)
	}
	a.state = state
	if !strings.Contains(a.View(), "plain http: fine for clients") {
		t.Errorf("the panel does not explain the transport:\n%s", a.View())
	}
}

// TestSwitchingToPlainHTTPClearsLetsEncrypt: the lines a previous transport
// left behind are emptied, so headscale does not keep asking for a
// certificate after the switch.
func TestSwitchingToPlainHTTPClearsLetsEncrypt(t *testing.T) {
	a, _ := fixtureApp(t, "headscale-config-letsencrypt.yaml")
	if wireguard.DetectTransport(a.state.Headscale.ControlPlane) != wireguard.TransportLetsEncrypt {
		t.Fatal("the fixture should read as Let's Encrypt")
	}
	a = startS(t, a, wireguard.TransportPlainHTTP)
	a = clearAndType(t, a, "http://203.0.113.10:443")
	a = enter(t, a) // 0.0.0.0:443 already
	a = enter(t, a) // tailnet.example.net

	removed, added := diffLines(a)
	if !contains(removed, `tls_letsencrypt_hostname: "vpn.example.com"`) ||
		!contains(added, `tls_letsencrypt_hostname: ""`) {
		t.Errorf("the Let's Encrypt hostname was not emptied:\n%s", a.confirm.Body)
	}
	// tls_cert_path and tls_key_path are already empty: nothing to clear.
	if strings.Contains(a.confirm.Body, "tls_cert_path") {
		t.Errorf("an already-empty key was rewritten:\n%s", a.confirm.Body)
	}
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// TestLetsEncryptRefusesAnIP: the refusal comes at the step, with the reason,
// and the form stays open on the typed value.
func TestLetsEncryptRefusesAnIP(t *testing.T) {
	a, _ := fixtureApp(t, "headscale-config.yaml")
	a = startS(t, a, wireguard.TransportLetsEncrypt)
	a = clearAndType(t, a, "https://203.0.113.10")
	if a.mode != modeInput || a.inputPurpose != inputServerURL {
		t.Fatalf("the refused URL did not reopen its step (mode %d)", a.mode)
	}
	if a.input.Model.Value() != "https://203.0.113.10" {
		t.Errorf("the typed value was lost: %q", a.input.Model.Value())
	}
	if !strings.Contains(a.input.Help, "IP address") || !strings.Contains(a.status, "IP address") {
		t.Errorf("no reason given: help %q, status %q", a.input.Help, a.status)
	}
}

// TestLetsEncryptFlow writes the hostname from server_url, the challenge and
// the account email, and refuses a base domain headscale would refuse.
func TestLetsEncryptFlow(t *testing.T) {
	a, _ := fixtureApp(t, "headscale-config.yaml")
	a = startS(t, a, wireguard.TransportLetsEncrypt)
	a = clearAndType(t, a, "https://vpn.example.org")
	if got := a.input.Model.Value(); got != "0.0.0.0:443" {
		t.Errorf("listen_addr prefill = %q", got)
	}
	a = enter(t, a)
	if a.pickerPurpose != pickerACMEChallenge ||
		a.picker.Selected() != challengeOptions[wireguard.ChallengeTLSALPN] {
		t.Fatalf("no challenge choice on TLS-ALPN-01 (purpose %d, %q)",
			a.pickerPurpose, a.picker.Selected())
	}
	a = enter(t, a)
	a = clearAndType(t, a, "not-an-email")
	if a.inputPurpose != inputACMEEmail {
		t.Fatalf("a bad email was not refused at its step")
	}
	a = clearAndType(t, a, "ops@example.org")

	// base_domain: the host sits inside example.org, which headscale refuses.
	a = clearAndType(t, a, "example.org")
	if a.inputPurpose != inputBaseDomain || !strings.Contains(a.status, "inside dns.base_domain") {
		t.Fatalf("a conflicting base_domain was not refused (purpose %d, status %q)",
			a.inputPurpose, a.status)
	}
	a = clearAndType(t, a, "tailnet.example.net")

	if a.mode != modeConfirm {
		t.Fatalf("no confirm (mode %d, status %q)", a.mode, a.status)
	}
	_, added := diffLines(a)
	for _, want := range []string{
		`server_url: "https://vpn.example.org"`,
		`acme_email: "ops@example.org"`,
		`tls_letsencrypt_hostname: "vpn.example.org"`,
		`tls_letsencrypt_challenge_type: "TLS-ALPN-01"`,
		`  base_domain: "tailnet.example.net"`,
	} {
		if !contains(added, want) {
			t.Errorf("the diff is missing %q:\n%s", want, a.confirm.Body)
		}
	}
}

// TestOwnCertificateIsCheckedBeforeItIsWritten: the pair tui-cert keeps in its
// root-only directory cannot be read by the service, which the form finds
// out from this machine before writing anything; a copy the service can read
// goes through.
func TestOwnCertificateIsCheckedBeforeItIsWritten(t *testing.T) {
	a, _ := fixtureApp(t, "")
	a = startS(t, a, wireguard.TransportOwnCert)
	a = clearAndType(t, a, "https://vpn.example.com")
	if got := a.input.Model.Value(); got != "0.0.0.0:443" {
		t.Errorf("listen_addr prefill = %q", got)
	}
	a = enter(t, a)
	a = clearAndType(t, a, "/etc/ssl/tui-cert/vpn.example.com.crt")
	if got := a.input.Model.Value(); got != "/etc/ssl/tui-cert/vpn.example.com.key" {
		t.Errorf("the key was not proposed next to the certificate: %q", got)
	}
	model, cmd := a.Update(tea.KeyMsg{Type: tea.KeyEnter})
	a = runPending(t, model.(*app), cmd)
	if a.inputPurpose != inputTLSCertPath || !strings.Contains(a.status, "cannot be entered by headscale") {
		t.Fatalf("an unreadable pair was not refused (purpose %d, status %q)",
			a.inputPurpose, a.status)
	}

	a = clearAndType(t, a, "/etc/headscale/tls/vpn.example.com.crt")
	model, cmd = a.Update(tea.KeyMsg{Type: tea.KeyEnter})
	a = runPending(t, model.(*app), cmd)
	if a.inputPurpose != inputBaseDomain {
		t.Fatalf("a readable pair did not move on (purpose %d, status %q)",
			a.inputPurpose, a.status)
	}
	a = enter(t, a)
	_, added := diffLines(a)
	for _, want := range []string{
		`tls_cert_path: "/etc/headscale/tls/vpn.example.com.crt"`,
		`tls_key_path: "/etc/headscale/tls/vpn.example.com.key"`,
		`listen_addr: "0.0.0.0:443"`,
	} {
		if !contains(added, want) {
			t.Errorf("the diff is missing %q:\n%s", want, a.confirm.Body)
		}
	}
}

// TestReverseProxyWantsLoopback and TestPlainHTTPWantsHTTP: each transport
// refuses the answer that contradicts it, at the step it was typed.
func TestReverseProxyWantsLoopback(t *testing.T) {
	a, _ := fixtureApp(t, "")
	a = startS(t, a, wireguard.TransportReverseProxy)
	a = clearAndType(t, a, "https://vpn.example.com")
	a = clearAndType(t, a, "0.0.0.0:8080")
	if a.inputPurpose != inputListenAddr || !strings.Contains(a.status, "loopback") {
		t.Errorf("a public bind behind a proxy was accepted (purpose %d, status %q)",
			a.inputPurpose, a.status)
	}
}

func TestPlainHTTPWantsHTTP(t *testing.T) {
	a, _ := fixtureApp(t, "")
	a = startS(t, a, wireguard.TransportPlainHTTP)
	a = clearAndType(t, a, "https://203.0.113.10")
	if a.inputPurpose != inputServerURL || !strings.Contains(a.status, "http://203.0.113.10") {
		t.Errorf("an https URL for plain http was accepted (purpose %d, status %q)",
			a.inputPurpose, a.status)
	}
}

// TestServerSettingsWarnsAboutAnUnreachableURL: a syntactically fine URL that
// no client can reach is the failure this form exists to prevent.
func TestServerSettingsWarnsAboutAnUnreachableURL(t *testing.T) {
	a := newTestApp(t)
	a = walkServerSettings(t, a, "https://127.0.0.1:8080")
	if a.mode != modeConfirm {
		t.Fatalf("mode = %d, want a confirm (status %q)", a.mode, a.status)
	}
	if !strings.Contains(a.confirm.Body, "WARNING") || !strings.Contains(a.confirm.Body, "loopback") {
		t.Errorf("a loopback server_url was not warned about:\n%s", a.confirm.Body)
	}
}

// TestPanelShowsTheTransport: the demo is behind a reverse proxy, and says so
// next to its base domain.
func TestPanelShowsTheTransport(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenUsers)
	view := a.View()
	for _, want := range []string{"transport   reverse proxy", "base_domain tailnet.example.net"} {
		if !strings.Contains(view, want) {
			t.Errorf("the panel does not show %q:\n%s", want, view)
		}
	}
}

// TestPlainHTTPWithOIDCSaysLoginsWillFail: with OIDC already configured, plain
// http (or a raw IP) is still allowed — clients are fine — but the form says
// before and after the answer that browser logins will not work, naming the
// redirect URI the IdP would refuse.
func TestPlainHTTPWithOIDCSaysLoginsWillFail(t *testing.T) {
	a, _ := fixtureApp(t, "") // the demo configuration has OIDC set up
	a = startS(t, a, wireguard.TransportPlainHTTP)
	if !strings.Contains(a.input.Help, "browser logins will fail") {
		t.Errorf("the server_url step does not warn about the login:\n%s", a.input.Help)
	}
	a = clearAndType(t, a, "http://203.0.113.10:443")
	a = clearAndType(t, a, "0.0.0.0:443")
	a = enter(t, a)
	if a.mode != modeConfirm {
		t.Fatalf("no confirm (mode %d, status %q)", a.mode, a.status)
	}
	for _, want := range []string{"WARNING", "browser logins will fail",
		"http://203.0.113.10:443/oidc/callback"} {
		if !strings.Contains(a.confirm.Body, want) {
			t.Errorf("the dialog does not say %q:\n%s", want, a.confirm.Body)
		}
	}
}

// TestPanelShowsTheRedirectURI: the value to register with the IdP is on
// screen, with whether an IdP will take it.
func TestPanelShowsTheRedirectURI(t *testing.T) {
	a := newTestApp(t)
	a.width = 140
	a.setScreen(wireguard.ScreenUsers)
	if !strings.Contains(a.View(), "https://vpn.example.com/oidc/callback — register it") {
		t.Errorf("the panel does not show the redirect URI:\n%s", a.View())
	}
	a.state.Headscale.ControlPlane.ServerURL = "http://203.0.113.10:443"
	if !strings.Contains(a.View(), "refuse an http redirect") {
		t.Errorf("the panel does not flag an http redirect URI:\n%s", a.View())
	}
}
