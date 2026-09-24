package wireguard

import (
	"strings"
)

// This file is what `O` knows about identity providers before it asks
// anything. Two findings from a real control plane federated to Google made
// it necessary:
//
//   - Google's ID token carries no groups claim. An allowed_groups entry —
//     kept from a placeholder, or typed out of habit — makes headscale refuse
//     every login, the allowed users included.
//   - headscale applies allowed_domains, allowed_groups and allowed_users
//     together: a login has to match every list that is not empty. With
//     allowed_domains set to a Workspace domain, a personal Google address in
//     allowed_users is refused ("unauthorised domain"), even though it is
//     listed by name.

// OIDCProvider is a preset for one identity provider: what `O` can fill in by
// itself, and what it has to tell the operator.
type OIDCProvider struct {
	// ID is the preset's stable name.
	ID string
	// Label is the picker's option text.
	Label string
	// Issuer is the fixed issuer URL, or "" when the operator types it.
	Issuer string
	// GroupsClaim reports whether the IdP's ID token can carry a groups
	// claim at all. When it cannot, allowed_groups can only refuse logins, so
	// the preset skips that step and clears the list.
	GroupsClaim bool
	// Gate says which allow list decides who gets in, for the dialog.
	Gate string
	// Console says where the OAuth client is created, for the dialog.
	Console string
}

// The providers `O` offers. Keycloak, Authentik and Microsoft fit the generic
// flow today and can get presets of their own later.
var (
	// ProviderGoogle is Google accounts and Google Workspace.
	ProviderGoogle = OIDCProvider{
		ID:          "google",
		Label:       "Google — accounts.google.com (Workspace or personal accounts)",
		Issuer:      "https://accounts.google.com",
		GroupsClaim: false,
		Gate: "Google's ID token has no groups claim, so allowed_groups is left empty " +
			"(any group there would refuse every login): allowed_domains (your Workspace " +
			"domain) or allowed_users is the gate.",
		Console: "Create it in the Google Cloud console under APIs & Services › " +
			"Credentials › OAuth client ID, type \"Web application\".",
	}
	// ProviderGeneric is any OpenID Connect provider: the issuer is typed.
	ProviderGeneric = OIDCProvider{
		ID:          "generic",
		Label:       "generic OIDC — any OpenID Connect provider (Keycloak, Authentik, …)",
		GroupsClaim: true,
		Gate: "allowed_domains, allowed_groups and allowed_users are the gate; the " +
			"groups only work when the IdP puts a groups claim in its ID token.",
		Console: "Create it in your IdP as a confidential client using the " +
			"authorization-code flow.",
	}
)

// OIDCProviders lists the presets in the order the picker offers them.
func OIDCProviders() []OIDCProvider {
	return []OIDCProvider{ProviderGoogle, ProviderGeneric}
}

// ProviderForIssuer is the preset an issuer URL belongs to: Google for
// accounts.google.com, the generic one for anything else.
func ProviderForIssuer(issuer string) OIDCProvider {
	if strings.EqualFold(URLHost(issuer), URLHost(ProviderGoogle.Issuer)) {
		return ProviderGoogle
	}
	return ProviderGeneric
}

// NoGroupsIdP reports whether an issuer is an IdP known to send no groups
// claim, which makes a non-empty allowed_groups refuse every login.
func NoGroupsIdP(issuer string) bool {
	return issuer != "" && !ProviderForIssuer(issuer).GroupsClaim
}

// AllowListsRule is the sentence every place that edits or shows the allow
// lists says: they are combined with AND, not OR.
const AllowListsRule = "headscale applies allowed_domains, allowed_groups and allowed_users " +
	"together: a login has to match every list that is not empty."

// UsersOutsideDomains lists the allowed_users entries that a non-empty
// allowed_domains refuses: headscale checks the domain of the address the IdP
// reports against allowed_domains before it looks at allowed_users, so a user
// listed by name is still refused when the domain is not there too. An entry
// that is not an address is left out, having no domain to compare.
func UsersOutsideDomains(users, domains []string) []string {
	if len(domains) == 0 {
		return nil
	}
	allowed := map[string]bool{}
	for _, d := range domains {
		allowed[strings.ToLower(strings.TrimSpace(d))] = true
	}
	var outside []string
	for _, u := range users {
		at := strings.LastIndexByte(u, '@')
		if at < 0 || at == len(u)-1 {
			continue
		}
		if !allowed[strings.ToLower(u[at+1:])] {
			outside = append(outside, u)
		}
	}
	return outside
}

// RedirectProblem says why an IdP will refuse the redirect URI this
// server_url implies, or "" when it will not: Google and most IdPs accept
// only https on a DNS name, and no browser can reach loopback.
func RedirectProblem(serverURL string) string {
	uri := RedirectURI(serverURL)
	host := URLHost(serverURL)
	switch {
	case serverURL == "":
		return "there is no server_url to build the redirect URI from"
	case IsLoopbackHost(host):
		return "the redirect URI " + uri + " points at loopback, which no browser can reach"
	case !ServerURLIsHTTPS(serverURL):
		return "the redirect URI " + uri + " is plain http"
	case IsIPHost(host):
		return "the redirect URI " + uri + " names an IP address"
	}
	return ""
}

// OIDCWarnings are the allow-list mistakes worth flagging next to a
// configuration: a groups list the IdP can never satisfy, and users that
// allowed_domains refuses despite being listed.
func OIDCWarnings(o OIDCConfig) []string {
	var warnings []string
	if len(o.AllowedGroups) > 0 && NoGroupsIdP(o.Issuer) {
		warnings = append(warnings, "allowed_groups is set, but "+URLHost(o.Issuer)+
			" sends no groups claim: headscale refuses every login — O clears it")
	}
	if outside := UsersOutsideDomains(o.AllowedUsers, o.AllowedDomains); len(outside) > 0 {
		warnings = append(warnings, "allowed_users "+strings.Join(outside, " ")+
			": the domain is not in allowed_domains, so headscale refuses them anyway")
	}
	return warnings
}

// OIDCReadiness is --check's answer to "will a browser login work", reduced to
// facts that name nothing of the host.
type OIDCReadiness struct {
	// IssuerReachable is whether the issuer's discovery document answered
	// from this machine. It is only filled in when --check was asked to go
	// on the network for it (--probe-issuer); otherwise it is absent.
	IssuerReachable *bool `json:"issuerReachable,omitempty"`
	// RedirectHTTPS is whether the redirect URI is one Google and most IdPs
	// accept: https, on a DNS name, not loopback.
	RedirectHTTPS bool `json:"redirectHttps"`
	// AllowListsNonEmpty is whether any allow list restricts who logs in.
	// With all three empty, anyone the IdP authenticates gets in.
	AllowListsNonEmpty bool `json:"allowListsNonEmpty"`
	// GroupsWithNoGroupsIdP is the Google finding: allowed_groups set for an
	// IdP that sends no groups claim, which refuses every login.
	GroupsWithNoGroupsIdP bool `json:"groupsWithNoGroupsIdp"`
	// UsersOutsideDomains counts the allowed_users that allowed_domains
	// refuses anyway. The addresses themselves are not printed: they name
	// people.
	UsersOutsideDomains int `json:"usersOutsideDomains"`
}

// ReadinessOf computes the readiness from a configuration. The issuer probe
// is the caller's to add.
func ReadinessOf(cp ControlPlane) OIDCReadiness {
	o := cp.OIDC
	return OIDCReadiness{
		RedirectHTTPS: RedirectProblem(cp.ServerURL) == "",
		AllowListsNonEmpty: len(o.AllowedDomains) > 0 || len(o.AllowedGroups) > 0 ||
			len(o.AllowedUsers) > 0,
		GroupsWithNoGroupsIdP: len(o.AllowedGroups) > 0 && NoGroupsIdP(o.Issuer),
		UsersOutsideDomains:   len(UsersOutsideDomains(o.AllowedUsers, o.AllowedDomains)),
	}
}
