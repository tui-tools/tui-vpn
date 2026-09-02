package main

import (
	"context"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
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
	serverURL, listenAddr string

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
	case inputOIDCDomains, inputOIDCGroups, inputOIDCUsers, inputOIDCSecret:
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

// --- the server-settings form (S) -------------------------------------------

// startServerSettings opens the first step of the server-settings form.
func (a *app) startServerSettings() tea.Cmd {
	if !a.controlPlaneEditable() {
		return nil
	}
	cp := a.state.Headscale.ControlPlane
	a.cpDraft = controlPlaneDraft{}
	a.openInput(inputServerURL, "Server settings — server_url",
		"https://vpn.example.com", cp.ServerURL,
		"The base URL clients reach this control plane on, and the URL the IdP will "+
			"redirect a browser back to. It has to be https and it has to resolve from "+
			"the clients' own networks: tui-cert issues the certificate, tui-firewall "+
			"opens the port.")
	return nil
}

// tookServerURL validates step 1 and opens step 2.
func (a *app) tookServerURL(value string) tea.Cmd {
	if !wireguard.ValidServerURL(value) {
		a.setStatusf(ui.StatusError, "not a valid server_url: %q", value)
		return nil
	}
	a.cpDraft.serverURL = value
	if warning := a.serverURLWarning(value); warning != "" {
		a.setStatus(ui.StatusWarn, warning)
	}
	listen := a.state.Headscale.ControlPlane.ListenAddr
	if listen == "" {
		listen = "0.0.0.0:8080"
	}
	a.openInput(inputListenAddr, "Server settings — listen_addr",
		"0.0.0.0:8080", listen,
		"The address headscale binds. Bind it to a loopback or an internal address when "+
			"a reverse proxy terminates TLS in front of it, and to 0.0.0.0 when it does not.")
	return nil
}

// tookListenAddr validates step 2 and opens the confirm chain.
func (a *app) tookListenAddr(value string) tea.Cmd {
	if !wireguard.ValidListenAddr(value) {
		a.setStatusf(ui.StatusError, "not a valid listen_addr: %q", value)
		return nil
	}
	a.cpDraft.listenAddr = value

	settings := wireguard.ServerSettings{
		ServerURL: a.cpDraft.serverURL, ListenAddr: a.cpDraft.listenAddr}
	edits, err := settings.Edits()
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	intro := "Step 1 of 2 — rewrite " + wireguard.HeadscaleConfigPath + ". Only the lines " +
		"below change; everything else in the file, comments included, is kept byte for byte."
	if warning := a.serverURLWarning(a.cpDraft.serverURL); warning != "" {
		intro = "WARNING: " + warning + "\n\n" + intro
	}
	return a.confirmConfigWrite(intro, edits)
}

// --- the OIDC form (O) ------------------------------------------------------

// startOIDCSettings opens the first step of the identity-provider form.
func (a *app) startOIDCSettings() tea.Cmd {
	if !a.controlPlaneEditable() {
		return nil
	}
	oidc := a.state.Headscale.ControlPlane.OIDC
	a.cpDraft = controlPlaneDraft{
		onlyStart: oidc.OnlyStartIfAvailable,
		pkce:      oidc.PKCE,
	}
	a.openInput(inputOIDCIssuer, "Identity provider — issuer URL",
		"https://idp.example.com/realms/main", oidc.Issuer,
		"The IdP's issuer URL — the one its discovery document is served under. "+
			"tui-vpn reads "+wireguard.OIDCDiscoveryPath+" from it before saving, from this "+
			"machine, because this machine is the one that will have to reach the IdP.")
	return nil
}

// tookOIDCIssuer validates the issuer and asks for the client id.
func (a *app) tookOIDCIssuer(value string) tea.Cmd {
	if !wireguard.ValidIssuerURL(value) {
		a.setStatusf(ui.StatusError, "not a valid issuer URL: %q", value)
		return nil
	}
	a.cpDraft.issuer = value
	a.openInput(inputOIDCClientID, "Identity provider — client id",
		"headscale", a.state.Headscale.ControlPlane.OIDC.ClientID,
		"The OAuth client the IdP issued for headscale.")
	return nil
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
	a.openInput(inputOIDCDomains, "Identity provider — allowed domains",
		"example.com, partner.example", strings.Join(
			a.state.Headscale.ControlPlane.OIDC.AllowedDomains, ", "),
		"Only users whose email domain is on this list may log in. Empty means the IdP's "+
			"own decision is the only gate.")
	return nil
}

// tookOIDCDomains records the domains and asks for the groups.
func (a *app) tookOIDCDomains(value string) tea.Cmd {
	a.cpDraft.domains = wireguard.SplitList(value)
	a.openInput(inputOIDCGroups, "Identity provider — allowed groups",
		"vpn-users", strings.Join(a.state.Headscale.ControlPlane.OIDC.AllowedGroups, ", "),
		"Groups the IdP must claim for a user. Empty means no group is required.")
	return nil
}

// tookOIDCGroups records the groups and asks for the users.
func (a *app) tookOIDCGroups(value string) tea.Cmd {
	a.cpDraft.groups = wireguard.SplitList(value)
	a.openInput(inputOIDCUsers, "Identity provider — allowed users",
		"ana@example.com", strings.Join(a.state.Headscale.ControlPlane.OIDC.AllowedUsers, ", "),
		"An explicit allow list of individual users. Empty means the domains and groups "+
			"above are the whole rule.")
	return nil
}

// tookOIDCUsers records the users and asks for the scope.
func (a *app) tookOIDCUsers(value string) tea.Cmd {
	a.cpDraft.users = wireguard.SplitList(value)
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

	if !a.cpDraft.replaceSecret {
		return a.confirmConfigWrite(discovery+"\n\nStep 1 of 2 — rewrite "+
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
	cmd := a.openConfirmWith(discovery+"\n\nStep 1 of 3 — write the client secret to "+
		wireguard.OIDCClientSecretPath+", mode 600, owned by "+serviceAccount(cp)+" — the "+
		"account this host's headscale unit actually runs as, so the service can read it "+
		"after the restart. The secret travels on the command's standard input, so it is "+
		"not on the command line below and not in this dialog; config.yaml will reference "+
		"the file instead of carrying the value.",
		secret, err)
	if a.mode == modeConfirm {
		a.after = func(string) tea.Cmd {
			return a.confirmConfigWrite("Step 2 of 3 — rewrite "+
				wireguard.HeadscaleConfigPath+". Only the lines below change.", edits)
		}
	} else {
		a.cpDraft.forgetSecret()
	}
	return cmd
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
func (a *app) confirmRestartHeadscale() tea.Cmd {
	a.cpDraft.forgetSecret()
	restart, err := wireguard.BuildRestartHeadscale()
	return a.openConfirmWith(
		"Last step — restart headscale so it reads the new configuration. Every node "+
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
	if w := wireguard.ServerURLWarning(url); w != "" {
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
