package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/runner"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-vpn/internal/wireguard"
)

// This file is the "manage, not view" half of the control plane. The users
// screen used to show `oidc: no` and leave it there — a fact with no way to
// act on it. `S` and `O` are the way to act on it: they collect what
// headscale's configuration needs, show the minimal diff of config.yaml the
// change would make, and apply it only after that diff is confirmed.
//
// PRIVACY: the OIDC client secret is typed with the echo masked, kept in this
// draft only long enough to build the one command that writes it, and dropped
// the moment that command exists — including when the flow is cancelled. It is
// never in a status line, never in a confirm body, never in an argv and never
// in config.yaml: config.yaml gets `client_secret_path`, and the value lives
// in a root-only file the tool will not read back.

// controlPlaneDraft collects the answers of the two control-plane forms.
type controlPlaneDraft struct {
	// The server-settings form: the transport, and what it needs.
	transport             wireguard.Transport
	serverURL, listenAddr string
	challenge, acmeEmail  string
	certPath, keyPath     string
	baseDomain            string

	// provider is the identity-provider preset O started from.
	provider                      wireguard.OIDCProvider
	issuer, clientID              string
	domains, groups, users, scope []string
	onlyStart, pkce               bool
	// clientSecret is the one field that is a credential. See the file's
	// PRIVACY note: it exists here for the few keystrokes between being typed
	// and being handed to the write command's stdin, and nowhere else.
	clientSecret string
	// replaceSecret reports that a new secret was typed, so the flow writes
	// the secret file before it writes config.yaml.
	replaceSecret bool
}

// forgetSecret drops the typed secret. It is called on every exit from the
// flow — accepted, cancelled or abandoned — so a secret never outlives the
// dialog that collected it.
func (d *controlPlaneDraft) forgetSecret() {
	d.clientSecret = ""
	d.replaceSecret = false
}

// acceptsEmpty reports whether an empty answer is a real answer rather than a
// cancellation. The allow lists and the client secret are the cases: "no
// domains" and "keep the secret that is already set" are both things an
// operator means to say.
func acceptsEmpty(purpose inputPurpose) bool {
	switch purpose {
	case inputOIDCDomains, inputOIDCGroups, inputOIDCUsers, inputOIDCSecret,
		inputACMEEmail, inputBaseDomain:
		return true
	case inputNewIfaceNetworks:
		// No networks means a forwarding server for any destination.
		return true
	case inputApproveRoutes:
		// No routes means revoke every approval, which is a real answer
		// (previewed as a danger dialog).
		return true
	}
	return false
}

// discoveredMsg carries the result of reading an issuer's discovery document.
type discoveredMsg struct {
	// ok reports that the issuer answered with something that looks like an
	// OpenID Provider's discovery document.
	ok bool
	// detail is what to tell the operator when it did not.
	detail string
}

// The server-settings form (S) lives in transport.go.

// --- the OIDC form (O) ------------------------------------------------------

// startOIDCSettings opens the first step of the identity-provider form: which
// provider. A preset fills in what it knows (Google's issuer and scope) and
// skips the steps that can only go wrong for it (allowed_groups, for an IdP
// that sends no groups claim).
func (a *app) startOIDCSettings() tea.Cmd {
	if !a.controlPlaneEditable() {
		return nil
	}
	oidc := a.state.Headscale.ControlPlane.OIDC
	a.cpDraft = controlPlaneDraft{
		onlyStart: oidc.OnlyStartIfAvailable,
		pkce:      oidc.PKCE,
	}
	options := make([]string, 0, len(wireguard.OIDCProviders()))
	for _, p := range wireguard.OIDCProviders() {
		options = append(options, p.Label)
	}
	current := wireguard.ProviderForIssuer(oidc.Issuer)
	a.picker = ui.NewPicker("Identity provider — which one", options, current.Label)
	a.pickerPurpose = pickerOIDCProvider
	a.mode = modePicker
	return nil
}

// tookOIDCProvider records the preset and opens its first step: the issuer
// for a generic provider, the client id for one whose issuer is fixed.
func (a *app) tookOIDCProvider(choice string) tea.Cmd {
	provider := wireguard.ProviderGeneric
	for _, p := range wireguard.OIDCProviders() {
		if p.Label == choice {
			provider = p
		}
	}
	a.cpDraft.provider = provider
	if provider.Issuer == "" {
		issuer := a.state.Headscale.ControlPlane.OIDC.Issuer
		if wireguard.ProviderForIssuer(issuer).ID != provider.ID {
			issuer = ""
		}
		a.openInput(inputOIDCIssuer, "Identity provider — issuer URL",
			"https://idp.example.com/realms/main", issuer,
			"The IdP's issuer URL — the one its discovery document is served under. "+
				"tui-vpn reads "+wireguard.OIDCDiscoveryPath+" from it before saving, from this "+
				"machine, because this machine is the one that will have to reach the IdP.")
		return nil
	}
	return a.tookOIDCIssuer(provider.Issuer)
}

// tookOIDCIssuer validates the issuer and asks for the client id.
func (a *app) tookOIDCIssuer(value string) tea.Cmd {
	if problem := wireguard.ServerURLProblem(value); problem != "" {
		// The same host check as server_url: an issuer typed as a mistyped IP
		// address would only fail later, at every login.
		a.setStatus(ui.StatusError, "not a valid issuer URL: "+problem)
		return nil
	}
	// An issuer typed into the generic flow that belongs to a preset gets
	// that preset's rules: Google's issuer, typed by hand, still sends no
	// groups claim.
	if a.cpDraft.provider.ID == "" || a.cpDraft.provider.ID == wireguard.ProviderGeneric.ID {
		if preset := wireguard.ProviderForIssuer(value); preset.ID != wireguard.ProviderGeneric.ID {
			a.cpDraft.provider = preset
			a.setStatusf(ui.StatusInfo, "%s is %s: its preset's rules apply", value,
				strings.SplitN(preset.Label, " ", 2)[0])
		}
	}
	// An IdP that refuses a plain-http or raw-IP redirect URI cannot log
	// anybody in on such a server_url: say so now, not after the restart.
	if !a.cpDraft.provider.GroupsClaim && a.cpDraft.provider.Issuer != "" {
		serverURL := a.state.Headscale.ControlPlane.ServerURL
		if problem := wireguard.RedirectProblem(serverURL); problem != "" {
			a.cpDraft.provider = wireguard.OIDCProvider{}
			a.setStatus(ui.StatusError, "Google refuses this server's redirect: "+problem+
				". It accepts only https on a DNS name — set that up with S first")
			return nil
		}
	}
	a.cpDraft.issuer = value
	a.openInput(inputOIDCClientID, "Identity provider — client id",
		"headscale", a.state.Headscale.ControlPlane.OIDC.ClientID,
		"The OAuth client the IdP issued for headscale. "+a.cpDraft.provider.Console+
			"\n\n"+a.redirectHelp())
	return nil
}

// redirectHelp is the redirect URI to register with the OAuth client, shown
// in the dialog itself: the one value an operator otherwise has to work out
// and type into the IdP's console by hand.
func (a *app) redirectHelp() string {
	serverURL := a.state.Headscale.ControlPlane.ServerURL
	uri := wireguard.RedirectURI(serverURL)
	if uri == "" {
		return "No server_url is set yet, so there is no redirect URI to register: run S first."
	}
	help := "Register " + uri + " as the OAuth client's redirect URI."
	if problem := wireguard.RedirectProblem(serverURL); problem != "" {
		help += " WARNING: " + problem + ", which Google and most IdPs refuse."
	}
	return help
}

// tookOIDCClientID validates the client id and asks for the secret.
func (a *app) tookOIDCClientID(value string) tea.Cmd {
	if !wireguard.ValidClientID(value) {
		a.setStatusf(ui.StatusError, "not a valid client id: %q", value)
		return nil
	}
	a.cpDraft.clientID = value

	help := "Typed masked, written to " + wireguard.OIDCClientSecretPath + " (mode 600, owned " +
		"by " + serviceAccount(a.state.Headscale.ControlPlane) + " — the account this host's " +
		"headscale unit runs as) and referenced from config.yaml as client_secret_path, so " +
		"it is never in the configuration file and never shown again — not even to you."
	if a.state.Headscale.ControlPlane.OIDC.ClientSecretSet {
		help = "A secret is already set. Leave this empty to keep it, or type a new one to " +
			"replace it. " + help
	}
	a.openMaskedInput(inputOIDCSecret, "Identity provider — client secret", "•••••••", help)
	return nil
}

// tookOIDCSecret records a new secret, or keeps the one already configured.
func (a *app) tookOIDCSecret(value string) tea.Cmd {
	switch {
	case value != "":
		if !wireguard.ValidClientSecret(value) {
			a.setStatus(ui.StatusError, "not a valid client secret")
			return nil
		}
		a.cpDraft.clientSecret = value
		a.cpDraft.replaceSecret = true
	case !a.state.Headscale.ControlPlane.OIDC.ClientSecretSet:
		a.setStatus(ui.StatusError,
			"a client secret is required: there is none set to keep")
		return nil
	}
	help := "Only users whose email domain is on this list may log in. Empty means no " +
		"domain rule. " + wireguard.AllowListsRule
	if !a.cpDraft.provider.GroupsClaim {
		help = "Your Google Workspace domain: only its accounts may log in. Empty means no " +
			"domain rule, and then allowed_users has to name who gets in. " +
			wireguard.AllowListsRule
	}
	a.openInput(inputOIDCDomains, "Identity provider — allowed domains",
		"example.com, partner.example", strings.Join(
			a.state.Headscale.ControlPlane.OIDC.AllowedDomains, ", "), help)
	return nil
}

// tookOIDCDomains records the domains and asks for the groups — or, for an
// IdP that sends no groups claim, clears them and goes on to the users.
func (a *app) tookOIDCDomains(value string) tea.Cmd {
	a.cpDraft.domains = wireguard.SplitList(value)
	if !a.cpDraft.provider.GroupsClaim {
		// Any group here would refuse every login: the IdP never claims one.
		a.cpDraft.groups = nil
		return a.askOIDCUsers()
	}
	a.openInput(inputOIDCGroups, "Identity provider — allowed groups",
		"vpn-users", strings.Join(a.state.Headscale.ControlPlane.OIDC.AllowedGroups, ", "),
		"Groups the IdP must claim for a user. Empty means no group is required. Only "+
			"set this when your IdP puts a groups claim in its ID token: without one, any "+
			"group here refuses every login. "+wireguard.AllowListsRule)
	return nil
}

// tookOIDCGroups records the groups and asks for the users.
func (a *app) tookOIDCGroups(value string) tea.Cmd {
	a.cpDraft.groups = wireguard.SplitList(value)
	return a.askOIDCUsers()
}

// askOIDCUsers opens the allowed-users step.
func (a *app) askOIDCUsers() tea.Cmd {
	a.openInput(inputOIDCUsers, "Identity provider — allowed users",
		"ana@example.com", strings.Join(a.state.Headscale.ControlPlane.OIDC.AllowedUsers, ", "),
		"An allow list of individual addresses. Empty means no per-user rule. It is not "+
			"an exception to the domains: "+wireguard.AllowListsRule+" A user outside "+
			"allowed_domains is refused even when listed here.")
	return nil
}

// tookOIDCUsers records the users and asks for the scope — or, for a preset
// whose scope is fixed, goes straight to the switches. A listed user whose
// domain allowed_domains refuses is warned about, not refused: it is a
// mistake headscale makes silently, at the login.
func (a *app) tookOIDCUsers(value string) tea.Cmd {
	a.cpDraft.users = wireguard.SplitList(value)
	if outside := wireguard.UsersOutsideDomains(a.cpDraft.users, a.cpDraft.domains); len(outside) > 0 {
		a.setStatusf(ui.StatusWarn, "headscale will refuse %s: not in allowed_domains",
			strings.Join(outside, ", "))
	}
	if a.cpDraft.provider.Issuer != "" {
		a.cpDraft.scope = wireguard.SplitList(wireguard.DefaultOIDCScope)
		a.openPicker(pickerOIDCOnlyStart, "only_start_if_oidc_is_available", a.cpDraft.onlyStart)
		return nil
	}
	scope := strings.Join(a.state.Headscale.ControlPlane.OIDC.Scope, " ")
	if scope == "" {
		scope = wireguard.DefaultOIDCScope
	}
	a.openInput(inputOIDCScope, "Identity provider — scope",
		wireguard.DefaultOIDCScope, scope,
		"The scopes requested at login. \""+wireguard.DefaultOIDCScope+"\" is what headscale "+
			"needs to learn a user's identity; add more only if your IdP requires them.")
	return nil
}

// tookOIDCScope records the scope and opens the first of the two switches.
func (a *app) tookOIDCScope(value string) tea.Cmd {
	scope := wireguard.SplitList(value)
	if len(scope) == 0 {
		a.setStatusf(ui.StatusError, "scope cannot be empty (try %q)", wireguard.DefaultOIDCScope)
		return nil
	}
	a.cpDraft.scope = scope
	a.openPicker(pickerOIDCOnlyStart, "only_start_if_oidc_is_available", a.cpDraft.onlyStart)
	return nil
}

// askOIDCPKCE opens the second switch.
func (a *app) askOIDCPKCE() tea.Cmd {
	a.openPicker(pickerOIDCPKCE, "pkce.enabled", a.cpDraft.pkce)
	return nil
}

// discoverIssuer reads the IdP's discovery document from this machine. It
// changes nothing, so it runs without a confirm; its failure is a warning
// rather than a refusal, because an IdP that is unreachable this minute is not
// a reason to be unable to write down its address.
func (a *app) discoverIssuer() tea.Cmd {
	cmd, err := wireguard.BuildDiscoverIssuer(a.cpDraft.issuer)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		a.cpDraft.forgetSecret()
		return nil
	}
	a.setStatusf(ui.StatusInfo, "checking %s…", wireguard.DiscoveryURL(a.cpDraft.issuer))
	backend := a.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		out, err := backend.Run(ctx, cmd)
		if err != nil {
			return discoveredMsg{detail: firstLineOf(err.Error())}
		}
		if !wireguard.DiscoveryLooksValid(out) {
			return discoveredMsg{detail: "the URL answered, but not with an OpenID Connect " +
				"discovery document"}
		}
		return discoveredMsg{ok: true}
	}
}

// confirmOIDCChain opens the confirm chain once discovery has answered: the
// secret file first when a new secret was typed, then config.yaml, then the
// restart.
func (a *app) confirmOIDCChain(msg discoveredMsg) tea.Cmd {
	settings := wireguard.OIDCSettings{
		Issuer:         a.cpDraft.issuer,
		ClientID:       a.cpDraft.clientID,
		Scope:          a.cpDraft.scope,
		AllowedDomains: a.cpDraft.domains,
		AllowedGroups:  a.cpDraft.groups,
		AllowedUsers:   a.cpDraft.users,
		OnlyStart:      a.cpDraft.onlyStart,
		PKCE:           a.cpDraft.pkce,
		// An inline secret already in the file is emptied: headscale refuses
		// to start with both a secret and a secret path, and a secret has no
		// business being in a configuration file anyway.
		ClearInlineSecret: a.state.Headscale.ControlPlane.OIDC.ClientSecretInline,
	}
	edits, err := settings.Edits()
	if err != nil {
		a.cpDraft.forgetSecret()
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}

	discovery := "The issuer answered " + wireguard.DiscoveryURL(a.cpDraft.issuer) + " correctly."
	if !msg.ok {
		discovery = "WARNING — the issuer could not be verified from this machine: " +
			msg.detail + "\nSaving anyway is fine; logins will fail until the IdP is " +
			"reachable from here."
	}
	discovery = a.oidcIntro() + "\n\n" + discovery

	// The count includes the tail: the restart, or the enable and the
	// restart a running but disabled unit needs.
	tail := wireguard.TailSteps(a.state.Headscale.ControlPlane)
	if !a.cpDraft.replaceSecret {
		return a.confirmConfigWrite(discovery+fmt.Sprintf("\n\nStep 1 of %d — rewrite ", 1+tail)+
			wireguard.HeadscaleConfigPath+". Only the lines below change.", edits)
	}

	// The secret goes first: config.yaml must never point at a file that is
	// not there yet.
	cp := a.state.Headscale.ControlPlane
	secret, err := wireguard.BuildWriteOIDCClientSecret(
		a.cpDraft.clientSecret, cp.ServiceUser, cp.ServiceGroup)
	// The value has done its job the moment the command holds it; the draft
	// gives it up here rather than at the end of the flow.
	a.cpDraft.forgetSecretValue()
	cmd := a.openConfirmWith(discovery+fmt.Sprintf("\n\nStep 1 of %d — write the client secret to ", 2+tail)+
		wireguard.OIDCClientSecretPath+", mode 600, owned by "+serviceAccount(cp)+" — the "+
		"account this host's headscale unit actually runs as, so the service can read it "+
		"after the restart. The secret travels on the command's standard input, so it is "+
		"not on the command line below and not in this dialog; config.yaml will reference "+
		"the file instead of carrying the value.",
		secret, err)
	if a.mode == modeConfirm {
		a.after = func(string) tea.Cmd {
			return a.confirmConfigWrite(fmt.Sprintf("Step 2 of %d — rewrite ", 2+tail)+
				wireguard.HeadscaleConfigPath+". Only the lines below change.", edits)
		}
	} else {
		a.cpDraft.forgetSecret()
	}
	return cmd
}

// oidcIntro is the top of the OIDC confirm chain: the provider and what gates
// access with it, the redirect URI to register, the AND rule of the allow
// lists, and the allow-list mistakes headscale would make silently.
func (a *app) oidcIntro() string {
	provider := a.cpDraft.provider
	if provider.ID == "" {
		provider = wireguard.ProviderForIssuer(a.cpDraft.issuer)
	}
	lines := []string{"Provider: " + strings.SplitN(provider.Label, " — ", 2)[0] + ". " +
		provider.Gate, a.redirectHelp(), wireguard.AllowListsRule}
	draft := wireguard.OIDCConfig{Issuer: a.cpDraft.issuer, AllowedDomains: a.cpDraft.domains,
		AllowedGroups: a.cpDraft.groups, AllowedUsers: a.cpDraft.users}
	for _, w := range wireguard.OIDCWarnings(draft) {
		lines = append(lines, "WARNING: "+w)
	}
	if len(a.cpDraft.domains) == 0 && len(a.cpDraft.groups) == 0 && len(a.cpDraft.users) == 0 {
		lines = append(lines, "WARNING: every allow list is empty, so anyone the IdP "+
			"authenticates can join the tailnet.")
	}
	return strings.Join(lines, "\n")
}

// serviceAccount renders the account a unit runs as, for a dialog.
func serviceAccount(cp wireguard.ControlPlane) string {
	user, group := cp.ServiceUser, cp.ServiceGroup
	if user == "" {
		user = wireguard.DefaultServiceUser
	}
	if group == "" {
		group = wireguard.DefaultServiceUser
	}
	return user + ":" + group
}

// forgetSecretValue drops the secret but keeps the flag that says the flow is
// writing one, which the remaining steps still need.
func (d *controlPlaneDraft) forgetSecretValue() { d.clientSecret = "" }

// --- the ownership fix (F) --------------------------------------------------

// startFixOwnership opens the chain of chowns that gives headscale's state,
// and the files this tool writes for it, back to the accounts that should own
// them, then offers the restart a service that failed on them needs.
func (a *app) startFixOwnership() tea.Cmd {
	if !a.controlPlaneEditable() {
		return nil
	}
	own := a.state.Headscale.ControlPlane.Ownership
	switch {
	case !own.Checked:
		a.setStatus(ui.StatusWarn, "ownership was not checked: stat could not read the "+
			"state paths (is sudo -n allowed?)")
		return nil
	case own.OK():
		a.setStatus(ui.StatusOK, "ownership is fine: nothing to fix")
		return nil
	}
	cmds, err := wireguard.BuildFixOwnership(own.Issues)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	return a.confirmFixStep(own.Issues, cmds, 0)
}

// confirmFixStep opens one chown of the chain, and chains the next one — or,
// after the last, the restart — behind it.
func (a *app) confirmFixStep(issues []wireguard.OwnershipIssue, cmds []runner.Command, i int) tea.Cmd {
	total := len(cmds) + wireguard.TailSteps(a.state.Headscale.ControlPlane)
	body := fmt.Sprintf("Step %d of %d — ", i+1, total)
	if i == 0 {
		body = ownershipSummary(issues) + "\n\n" + body
	}
	switch {
	case len(cmds[i].Argv) > 1 && cmds[i].Argv[1] == "-R":
		body += "give the whole state directory back to the account headscale runs as. " +
			"A root-run headscale leaves more behind than the files named above (its " +
			"write-ahead log, caches), and everything in there belongs to the service."
	default:
		body += "give this one file to the account that has to read it. It is not " +
			"recursive: nothing else changes owner."
	}
	cmd := a.openConfirmWith(body, cmds[i], nil)
	if a.mode == modeConfirm {
		if i+1 < len(cmds) {
			a.after = func(string) tea.Cmd { return a.confirmFixStep(issues, cmds, i+1) }
		} else {
			a.after = func(string) tea.Cmd { return a.confirmRestartHeadscale() }
		}
	}
	return cmd
}

// ownershipSummary lists what the check found, for the first dialog of the
// chain: the reader confirms a chown knowing which files it is for.
func ownershipSummary(issues []wireguard.OwnershipIssue) string {
	lines := []string{"Not owned by the account that needs them:"}
	for _, issue := range issues {
		lines = append(lines, "  "+issue.Path+"  "+issue.Owner+" → "+issue.Want+
			"  ("+string(issue.Role)+")")
	}
	return strings.Join(lines, "\n")
}

// --- the shared write-and-restart tail --------------------------------------

// confirmConfigWrite computes the edited configuration, shows the minimal diff
// and chains the restart behind it. The diff is the whole point of the dialog:
// a configuration file is not something to rewrite on trust, and the edit is
// built so that the lines shown are provably the only lines that differ.
func (a *app) confirmConfigWrite(intro string, edits []wireguard.ConfigEdit) tea.Cmd {
	cp := a.state.Headscale.ControlPlane
	updated, changes, err := wireguard.EditConfig(cp.Raw, edits)
	if err != nil {
		a.cpDraft.forgetSecret()
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	if len(changes) == 0 {
		a.cpDraft.forgetSecret()
		a.setStatus(ui.StatusInfo, cp.ConfigPath+" already says this — nothing to write")
		return nil
	}

	write, err := wireguard.BuildWriteHeadscaleConfig(updated)
	body := intro + "\n\n" + wireguard.RenderConfigDiff(cp.ConfigPath, changes)
	cmd := a.openConfirmWith(body, write, err)
	if a.mode == modeConfirm {
		a.after = func(string) tea.Cmd { return a.confirmRestartHeadscale() }
	} else {
		a.cpDraft.forgetSecret()
	}
	return cmd
}

// confirmRestartHeadscale is the last step: a configuration change does
// nothing until the unit that reads it restarts. It is optional — esc leaves
// the file written and the running server on the old configuration.
//
// A disabled unit gets more than a restart. A fresh package install leaves
// headscale disabled, so a restart alone brings the control plane up now and
// loses it at the next reboot. A disabled unit that is not running is enabled
// and started in one step (`systemctl enable --now`); one that is running is
// enabled and then restarted, because `enable --now` leaves a running unit
// alone and the new configuration would never be read.
func (a *app) confirmRestartHeadscale() tea.Cmd {
	a.cpDraft.forgetSecret()
	cp := a.state.Headscale.ControlPlane
	if !wireguard.ServiceNeedsEnable(cp.ServiceEnabled) {
		return a.confirmPlainRestart("Last step")
	}
	if cp.ServiceState != "active" {
		enable, err := wireguard.BuildEnableHeadscale(true)
		return a.openConfirmWith(
			"Last step — the headscale unit is disabled and "+orDash(cp.ServiceState)+
				", so it is enabled and started in one go: a plain restart would bring "+
				"the control plane up now and lose it at the next reboot. Esc leaves the "+
				"file written and the unit as it is.",
			enable, err)
	}
	enable, err := wireguard.BuildEnableHeadscale(false)
	cmd := a.openConfirmWith(
		"Next step — the headscale unit is running but disabled: it would not come back "+
			"after a reboot. This enables it at boot; the restart that reads the new "+
			"configuration follows as its own step. Esc skips both.",
		enable, err)
	if a.mode == modeConfirm {
		a.after = func(string) tea.Cmd { return a.confirmPlainRestart("Last step") }
	}
	return cmd
}

// confirmPlainRestart opens the restart itself.
func (a *app) confirmPlainRestart(step string) tea.Cmd {
	restart, err := wireguard.BuildRestartHeadscale()
	return a.openConfirmWith(
		step+" — restart headscale so it reads the new configuration. Every node "+
			"loses its control connection for as long as the restart takes; established "+
			"tunnels keep carrying traffic. Esc leaves the file written and the running "+
			"server on the old settings.",
		restart, err)
}

// --- helpers ----------------------------------------------------------------

// serverURLWarning collects every reason this server_url will not work: the
// ones that are true of any URL, and the one that depends on the rest of the
// configuration — a host inside dns.base_domain, which headscale refuses to
// start with at all.
func (a *app) serverURLWarning(url string) string {
	warnings := []string{}
	if url != "" {
		// A malformed host already in the file (written before the check
		// existed, or by hand) is the first thing worth flagging.
		if problem := wireguard.ServerURLProblem(url); problem != "" {
			warnings = append(warnings, "server_url is not valid: "+problem)
		}
	}
	if w := wireguard.ServerURLWarning(url,
		a.state.Headscale.ControlPlane.OIDC.Configured()); w != "" {
		warnings = append(warnings, w)
	}
	if w := wireguard.BaseDomainConflict(url,
		a.state.Headscale.ControlPlane.BaseDomain); w != "" {
		warnings = append(warnings, w)
	}
	return strings.Join(warnings, "\n\n")
}

// controlPlaneEditable reports whether there is a configuration to edit, and
// says why not when there is not.
func (a *app) controlPlaneEditable() bool {
	if !a.state.Headscale.Present {
		a.setStatus(ui.StatusWarn, "no control plane")
		return false
	}
	cp := a.state.Headscale.ControlPlane
	if !cp.Readable {
		reason := cp.Error
		if reason == "" {
			reason = "it could not be read"
		}
		// Editing a file that could not be read would mean writing a guess
		// over somebody's configuration. The tool refuses rather than risk it.
		a.setStatusf(ui.StatusError, "cannot edit %s: %s", cp.ConfigPath, reason)
		return false
	}
	return true
}

// openInput opens a text input for one step of a control-plane form.
func (a *app) openInput(purpose inputPurpose, title, placeholder, value, help string) {
	a.input = ui.NewInput(title, placeholder, value)
	a.input.Help = help
	a.inputPurpose = purpose
	a.mode = modeInput
}

// openMaskedInput opens a text input whose echo is masked. It is used for
// exactly one field in this tool, and that field is never echoed back
// anywhere else either.
func (a *app) openMaskedInput(purpose inputPurpose, title, placeholder, help string) {
	a.openInput(purpose, title, placeholder, "", help)
	a.input.Model.EchoMode = textinput.EchoPassword
}

// openPicker opens a yes/no picker for one of the OIDC switches.
func (a *app) openPicker(purpose pickerPurpose, title string, current bool) {
	a.picker = ui.NewPicker(title, []string{pickerYes, pickerNo}, boolChoice(current))
	a.pickerPurpose = purpose
	a.mode = modePicker
}

// boolChoice maps a boolean to the picker's options.
func boolChoice(b bool) string {
	if b {
		return pickerYes
	}
	return pickerNo
}

// firstLineOf keeps a message to one line, the way the status line needs it.
func firstLineOf(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// handleControlPlaneInput routes a finished control-plane input to its step.
// It is the tail of handleInput: everything the browse view's own actions do
// not claim lands here.
func (a *app) handleControlPlaneInput(purpose inputPurpose, value string) tea.Cmd {
	switch purpose {
	case inputServerURL:
		return a.tookServerURL(value)
	case inputListenAddr:
		return a.tookListenAddr(value)
	case inputACMEEmail:
		return a.tookACMEEmail(value)
	case inputTLSCertPath:
		return a.tookCertPath(value)
	case inputTLSKeyPath:
		return a.tookKeyPath(value)
	case inputBaseDomain:
		return a.tookBaseDomain(value)
	case inputOIDCIssuer:
		return a.tookOIDCIssuer(value)
	case inputOIDCClientID:
		return a.tookOIDCClientID(value)
	case inputOIDCSecret:
		return a.tookOIDCSecret(value)
	case inputOIDCDomains:
		return a.tookOIDCDomains(value)
	case inputOIDCGroups:
		return a.tookOIDCGroups(value)
	case inputOIDCUsers:
		return a.tookOIDCUsers(value)
	case inputOIDCScope:
		return a.tookOIDCScope(value)
	}
	return nil
}
