package wireguard

import (
	"reflect"
	"strings"
	"testing"
)

func TestProviderForIssuer(t *testing.T) {
	for issuer, want := range map[string]string{
		"https://accounts.google.com":         "google",
		"https://accounts.google.com/":        "google",
		"https://idp.example.com/realms/main": "generic",
		"":                                    "generic",
	} {
		if got := ProviderForIssuer(issuer).ID; got != want {
			t.Errorf("ProviderForIssuer(%q) = %q, want %q", issuer, got, want)
		}
	}
	if !NoGroupsIdP("https://accounts.google.com") || NoGroupsIdP("https://idp.example.com") ||
		NoGroupsIdP("") {
		t.Error("NoGroupsIdP is wrong")
	}
}

// TestUsersOutsideDomains is the second finding from the real host: with
// allowed_domains set, a listed address from another domain is refused by
// headscale anyway, because the lists are combined with AND.
func TestUsersOutsideDomains(t *testing.T) {
	domains := []string{"example.com", "example.org"}
	users := []string{"ana@example.com", "bo@mail.example.net", "Cy@Example.ORG", "not-an-address"}
	got := UsersOutsideDomains(users, domains)
	if !reflect.DeepEqual(got, []string{"bo@mail.example.net"}) {
		t.Errorf("UsersOutsideDomains = %q", got)
	}
	if got := UsersOutsideDomains(users, nil); got != nil {
		t.Errorf("no domain rule refuses nobody, got %q", got)
	}
}

func TestRedirectProblem(t *testing.T) {
	for url, ok := range map[string]bool{
		"https://vpn.example.com":      true,
		"https://vpn.example.com:8443": true,
		"http://vpn.example.com":       false,
		"https://203.0.113.10":         false,
		"https://127.0.0.1:8080":       false,
		"":                             false,
	} {
		if problem := RedirectProblem(url); (problem == "") != ok {
			t.Errorf("RedirectProblem(%q) = %q, want ok=%v", url, problem, ok)
		}
	}
}

// TestOIDCWarningsAndReadiness: the Google groups finding and the AND
// finding, as the panel and --check report them.
func TestOIDCWarningsAndReadiness(t *testing.T) {
	cp := ControlPlane{Readable: true, ServerURL: "https://vpn.example.com",
		OIDC: OIDCConfig{Issuer: "https://accounts.google.com", ClientID: "x",
			AllowedDomains: []string{"example.com"}, AllowedGroups: []string{"vpn-users"},
			AllowedUsers: []string{"ana@example.com", "bo@mail.example.net"}}}
	warnings := OIDCWarnings(cp.OIDC)
	if len(warnings) != 2 || !strings.Contains(warnings[0], "no groups claim") ||
		!strings.Contains(warnings[1], "bo@mail.example.net") {
		t.Errorf("OIDCWarnings = %q", warnings)
	}
	r := ReadinessOf(cp)
	if !r.RedirectHTTPS || !r.AllowListsNonEmpty || !r.GroupsWithNoGroupsIdP ||
		r.UsersOutsideDomains != 1 || r.IssuerReachable != nil {
		t.Errorf("ReadinessOf = %+v", r)
	}
	cp.ServerURL = "http://203.0.113.10:443"
	cp.OIDC.AllowedDomains, cp.OIDC.AllowedGroups, cp.OIDC.AllowedUsers = nil, nil, nil
	r = ReadinessOf(cp)
	if r.RedirectHTTPS || r.AllowListsNonEmpty || r.GroupsWithNoGroupsIdP {
		t.Errorf("ReadinessOf (open, http) = %+v", r)
	}
}
