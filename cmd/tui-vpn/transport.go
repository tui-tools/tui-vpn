package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-vpn/internal/wireguard"
)

// This file is the server-settings form behind `S`: how clients reach the
// control plane. It starts with the transport, because the transport decides
// what every later step means — an https server_url makes no sense for plain
// http, a Let's Encrypt name cannot be an IP address, a reverse proxy wants
// headscale on loopback — and it ends with dns.base_domain, which headscale
// checks against the server_url host at startup.
//
// A step whose answer is refused reopens with the reason on top and the typed
// value still in it, so a mistake costs a correction rather than the form.

// transportOptions are the picker's options, one per transport.
var transportOptions = map[wireguard.Transport]string{
	wireguard.TransportPlainHTTP:    "plain http — an IP or a name, no TLS",
	wireguard.TransportLetsEncrypt:  "Let's Encrypt — headscale gets its own certificate",
	wireguard.TransportOwnCert:      "own certificate — tls_cert_path and tls_key_path",
	wireguard.TransportReverseProxy: "reverse proxy — TLS ends in front, headscale on loopback",
}

// challengeOptions are the ACME picker's options.
var challengeOptions = map[string]string{
	wireguard.ChallengeTLSALPN: wireguard.ChallengeTLSALPN + " — answered on the TLS port; use it when port 80 is closed",
	wireguard.ChallengeHTTP:    wireguard.ChallengeHTTP + " — needs port 80 reachable from the internet",
}

// tlsCheckedMsg carries the result of reading a certificate's and a key's
// ownership: problem is why the service account cannot use them, or empty.
type tlsCheckedMsg struct{ problem string }

// startServerSettings opens the first step: the transport.
func (a *app) startServerSettings() tea.Cmd {
	if !a.controlPlaneEditable() {
		return nil
	}
	current := wireguard.DetectTransport(a.state.Headscale.ControlPlane)
	a.cpDraft = controlPlaneDraft{}
	options := make([]string, 0, len(transportOptions))
	for _, t := range wireguard.Transports() {
		options = append(options, transportOptions[t])
	}
	a.picker = ui.NewPicker("Server settings — how clients reach headscale "+
		"(now: "+current.Label()+")", options, transportOptions[current])
	a.pickerPurpose = pickerTransport
	a.mode = modePicker
	return nil
}

// tookTransport records the transport and asks for server_url.
func (a *app) tookTransport(choice string) tea.Cmd {
	for t, label := range transportOptions {
		if label == choice {
			a.cpDraft.transport = t
		}
	}
	if a.cpDraft.transport == "" {
		a.setStatus(ui.StatusError, "not a transport: "+choice)
		return nil
	}
	// The proposed value is the one in the file; when that one is malformed
	// (written by hand, or before the host check existed), the step opens with
	// the reason instead of offering it as if it were fine.
	current := a.state.Headscale.ControlPlane.ServerURL
	var problem error
	if current != "" {
		if p := wireguard.ServerURLProblem(current); p != "" {
			problem = fmt.Errorf("the server_url in the file is not valid: %s", p)
		}
	}
	a.askServerURL(current, problem)
	return nil
}

// settings is the draft as the settings the package validates.
func (a *app) settings() wireguard.TransportSettings {
	d := a.cpDraft
	return wireguard.TransportSettings{
		ServerSettings: wireguard.ServerSettings{ServerURL: d.serverURL, ListenAddr: d.listenAddr},
		Transport:      d.transport,
		Challenge:      d.challenge,
		ACMEEmail:      d.acmeEmail,
		CertPath:       d.certPath,
		KeyPath:        d.keyPath,
		BaseDomain:     d.baseDomain,
		MagicDNS:       a.state.Headscale.ControlPlane.MagicDNS,
	}
}

// openRetry opens a step's input, with the reason its last answer was refused
// on top of the help when there is one.
func (a *app) openRetry(purpose inputPurpose, title, placeholder, value, help string,
	problem error) {
	if problem != nil {
		a.setStatus(ui.StatusError, problem.Error())
		help = "✗ " + problem.Error() + "\n\n" + help
	}
	a.openInput(purpose, title, placeholder, value, help)
}

// askServerURL opens the server_url step, explained for the chosen transport.
func (a *app) askServerURL(value string, problem error) {
	placeholder := "https://vpn.example.com"
	var help string
	switch a.cpDraft.transport {
	case wireguard.TransportPlainHTTP:
		placeholder = "http://203.0.113.10:443"
		help = "The URL clients reach the control plane on: an IP or a name, over http. " +
			"That is fine for clients — the Tailscale control protocol is Noise-encrypted " +
			"end to end — and only an OIDC login in a browser needs https. Include the " +
			"port unless it is 80."
	case wireguard.TransportLetsEncrypt:
		help = "https:// and a public DNS name that resolves to this server: headscale " +
			"asks Let's Encrypt for that name's certificate by itself. An IP address " +
			"cannot get one."
	case wireguard.TransportOwnCert:
		help = "https:// and the name on your certificate. tui-cert issues the " +
			"certificate; the next steps ask for its files."
	case wireguard.TransportReverseProxy:
		help = "https:// and the name your proxy serves. The proxy terminates TLS and " +
			"forwards to headscale, which listens on loopback behind it."
	}
	help += " It is also where an IdP redirects a browser back to (" +
		wireguard.RedirectURI("<server_url>") + ")."
	if a.state.Headscale.ControlPlane.OIDC.Configured() {
		// The login is the one thing plain http and a raw IP break, and OIDC
		// is already set up here: say so before the answer, not after it.
		help = "OIDC is configured: browser logins will fail over plain http or on a " +
			"raw IP address, because Google and most IdPs refuse such a redirect URI. " +
			"Use https on a DNS name to keep them working.\n\n" + help
	}
	a.openRetry(inputServerURL, "Server settings — server_url ("+
		a.cpDraft.transport.Label()+")", placeholder, value, help, problem)
}

// tookServerURL checks server_url against the transport and asks for
// listen_addr.
func (a *app) tookServerURL(value string) tea.Cmd {
	a.cpDraft.serverURL = value
	if err := a.settings().CheckServerURL(); err != nil {
		a.askServerURL(value, err)
		return nil
	}
	if warning := wireguard.ServerURLWarning(value,
		a.state.Headscale.ControlPlane.OIDC.Configured()); warning != "" {
		a.setStatus(ui.StatusWarn, warning)
	}
	proposed := a.defaultListenAddr()
	var problem error
	if p := wireguard.ListenAddrProblem(proposed); p != "" {
		problem = fmt.Errorf("the listen_addr in the file is not valid: %s", p)
	}
	a.askListenAddr(proposed, problem)
	return nil
}

// defaultListenAddr proposes the bind address the transport usually wants.
// Behind a proxy that is loopback; otherwise a loopback bind left over from
// the stock file (127.0.0.1:8080, which no client can reach) becomes the
// wildcard on server_url's own port — the one-keystroke answer for the common
// case of http://<public-ip>:443.
func (a *app) defaultListenAddr() string {
	current := a.state.Headscale.ControlPlane.ListenAddr
	loopback := wireguard.IsLoopbackHost(wireguard.ListenHost(current))
	if a.cpDraft.transport == wireguard.TransportReverseProxy {
		if current != "" && loopback {
			return current
		}
		return "127.0.0.1:8080"
	}
	if current == "" || (loopback && !wireguard.IsLoopbackHost(wireguard.URLHost(a.cpDraft.serverURL))) {
		return fmt.Sprintf("0.0.0.0:%d", wireguard.URLPort(a.cpDraft.serverURL))
	}
	return current
}

// askListenAddr opens the listen_addr step.
func (a *app) askListenAddr(value string, problem error) {
	help := "The address headscale binds: 0.0.0.0 and the port clients use, when " +
		"nothing sits in front of it. tui-firewall opens the port."
	if a.cpDraft.transport == wireguard.TransportReverseProxy {
		help = "Loopback, so only the proxy in front reaches headscale; point the proxy " +
			"at this address."
	}
	a.openRetry(inputListenAddr, "Server settings — listen_addr", "0.0.0.0:443", value,
		help, problem)
}

// tookListenAddr checks listen_addr and moves to the transport's own steps.
func (a *app) tookListenAddr(value string) tea.Cmd {
	a.cpDraft.listenAddr = value
	if err := a.settings().CheckListenAddr(); err != nil {
		a.askListenAddr(value, err)
		return nil
	}
	cp := a.state.Headscale.ControlPlane
	switch a.cpDraft.transport {
	case wireguard.TransportLetsEncrypt:
		current := wireguard.ChallengeTLSALPN
		if wireguard.DetectTransport(cp) == wireguard.TransportLetsEncrypt &&
			cp.TLSLetsEncryptChallenge != "" {
			current = cp.TLSLetsEncryptChallenge
		}
		a.picker = ui.NewPicker("Let's Encrypt — ACME challenge",
			[]string{challengeOptions[wireguard.ChallengeTLSALPN],
				challengeOptions[wireguard.ChallengeHTTP]},
			challengeOptions[current])
		a.pickerPurpose = pickerACMEChallenge
		a.mode = modePicker
	case wireguard.TransportOwnCert:
		a.askCertPath(cp.TLSCertPath, nil)
	default:
		a.askBaseDomain(cp.BaseDomain, nil)
	}
	return nil
}

// tookChallenge records the ACME challenge and asks for the account email.
func (a *app) tookChallenge(choice string) tea.Cmd {
	for challenge, label := range challengeOptions {
		if label == choice {
			a.cpDraft.challenge = challenge
		}
	}
	a.openInput(inputACMEEmail, "Let's Encrypt — acme_email (optional)",
		"ops@example.com", a.state.Headscale.ControlPlane.ACMEEmail,
		"The address Let's Encrypt writes to about the certificate (expiry "+
			"warnings, policy changes). Leave it empty to register without one.")
	return nil
}

// tookACMEEmail records the account email and asks for the base domain.
func (a *app) tookACMEEmail(value string) tea.Cmd {
	if !wireguard.ValidACMEEmail(value) {
		a.setStatusf(ui.StatusError, "not a valid acme_email: %q", value)
		a.openInput(inputACMEEmail, "Let's Encrypt — acme_email (optional)",
			"ops@example.com", value, "✗ not a valid email address\n\n"+
				"The address Let's Encrypt writes to about the certificate. Leave it "+
				"empty to register without one.")
		return nil
	}
	a.cpDraft.acmeEmail = value
	a.askBaseDomain(a.state.Headscale.ControlPlane.BaseDomain, nil)
	return nil
}

// askCertPath opens the certificate step.
func (a *app) askCertPath(value string, problem error) {
	a.openRetry(inputTLSCertPath, "Own certificate — tls_cert_path",
		"/etc/headscale/tls/vpn.example.com.crt", value,
		"The certificate (full chain) headscale serves. It has to be readable by "+
			serviceAccount(a.state.Headscale.ControlPlane)+", the account headscale runs "+
			"as, and outside /home and /tmp, which the packaged unit cannot see. tui-cert "+
			"issues one, and its install step copies the pair wherever headscale needs it.",
		problem)
}

// tookCertPath records the certificate and asks for the key.
func (a *app) tookCertPath(value string) tea.Cmd {
	if !wireguard.ValidTLSPath(value) {
		a.askCertPath(value, fmt.Errorf("not an absolute, plain path: %q", value))
		return nil
	}
	a.cpDraft.certPath = value
	key := a.state.Headscale.ControlPlane.TLSKeyPath
	if key == "" && strings.HasSuffix(value, ".crt") {
		key = strings.TrimSuffix(value, ".crt") + ".key"
	}
	a.askKeyPath(key, nil)
	return nil
}

// askKeyPath opens the key step.
func (a *app) askKeyPath(value string, problem error) {
	a.openRetry(inputTLSKeyPath, "Own certificate — tls_key_path",
		"/etc/headscale/tls/vpn.example.com.key", value,
		"The certificate's private key. Only its path is written to config.yaml; the "+
			"key itself is never read by this tool. It has to be readable by "+
			serviceAccount(a.state.Headscale.ControlPlane)+".",
		problem)
}

// tookKeyPath records the key, then checks both files from this machine.
func (a *app) tookKeyPath(value string) tea.Cmd {
	if !wireguard.ValidTLSPath(value) {
		a.askKeyPath(value, fmt.Errorf("not an absolute, plain path: %q", value))
		return nil
	}
	a.cpDraft.keyPath = value
	cert, key := a.cpDraft.certPath, value
	cp := a.state.Headscale.ControlPlane
	user, group := cp.ServiceUser, cp.ServiceGroup
	if user == "" {
		user, group = wireguard.DefaultServiceUser, wireguard.DefaultServiceUser
	}
	a.setStatus(ui.StatusInfo, "checking that "+user+" can read the certificate and key…")
	backend := a.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		stats := backend.Stat(ctx, wireguard.TLSStatPaths(cert, key))
		for _, p := range []string{cert, key} {
			if problem := wireguard.TLSFileProblem(p, stats, user, group); problem != "" {
				return tlsCheckedMsg{problem: problem}
			}
		}
		return tlsCheckedMsg{}
	}
}

// tookTLSCheck continues once the files were checked: to the base domain, or
// back to the certificate step with the reason it cannot be used.
func (a *app) tookTLSCheck(msg tlsCheckedMsg) tea.Cmd {
	if msg.problem != "" {
		a.askCertPath(a.cpDraft.certPath, fmt.Errorf("%s — give the files to the service "+
			"account, or install a copy it can read (tui-cert's install step does)", msg.problem))
		return nil
	}
	a.askBaseDomain(a.state.Headscale.ControlPlane.BaseDomain, nil)
	return nil
}

// askBaseDomain opens the last step: MagicDNS's domain.
func (a *app) askBaseDomain(value string, problem error) {
	help := "The MagicDNS domain: every node gets a name under it (laptop.<base_domain>). " +
		"It must not contain the server_url host — MagicDNS owns every name under it, so " +
		"headscale refuses to start that way. A private suffix such as tailnet.internal " +
		"is typical."
	if !a.state.Headscale.ControlPlane.MagicDNS {
		help += " dns.magic_dns is off, so it may be left empty."
	}
	a.openRetry(inputBaseDomain, "Server settings — dns.base_domain", "tailnet.internal",
		value, help, problem)
}

// tookBaseDomain checks the base domain and opens the confirm chain.
func (a *app) tookBaseDomain(value string) tea.Cmd {
	a.cpDraft.baseDomain = strings.ToLower(value)
	settings := a.settings()
	if err := settings.CheckBaseDomain(); err != nil {
		a.askBaseDomain(value, err)
		return nil
	}
	edits, err := settings.Edits()
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	return a.confirmConfigWrite(a.transportIntro(settings), edits)
}

// transportIntro is the confirm dialog's explanation above the diff: what the
// chosen transport means, and anything about it worth a second look.
func (a *app) transportIntro(s wireguard.TransportSettings) string {
	lines := []string{"Transport: " + s.Transport.Label() + "."}
	switch s.Transport {
	case wireguard.TransportPlainHTTP:
		lines = append(lines, "No TLS lines are written, and any a previous transport "+
			"left behind are emptied. Clients are fine over http: the control channel "+
			"is Noise-encrypted. Only an OIDC login in a browser needs https.")
	case wireguard.TransportLetsEncrypt:
		lines = append(lines, "headscale requests the certificate for "+
			wireguard.URLHost(s.ServerURL)+" itself, with "+s.Challenge+".")
		if s.Challenge == wireguard.ChallengeTLSALPN && wireguard.ListenPort(s.ListenAddr) != 443 {
			lines = append(lines, fmt.Sprintf("WARNING: %s is answered on port 443, and "+
				"listen_addr is on %d: it only works if 443 is forwarded there.",
				wireguard.ChallengeTLSALPN, wireguard.ListenPort(s.ListenAddr)))
		}
		if s.Challenge == wireguard.ChallengeHTTP {
			lines = append(lines, "HTTP-01 needs port 80 reachable from the internet "+
				"(tls_letsencrypt_listen, :http by default): tui-firewall opens it.")
		}
	case wireguard.TransportOwnCert:
		lines = append(lines, "The certificate and key were checked from this machine: "+
			serviceAccount(a.state.Headscale.ControlPlane)+" can read both.")
		for _, p := range []string{s.CertPath, s.KeyPath} {
			if wireguard.SandboxedPath(p) {
				lines = append(lines, "WARNING: "+p+" is under a directory the packaged "+
					"unit hides from the service (ProtectHome=, PrivateTmp=).")
			}
		}
	case wireguard.TransportReverseProxy:
		lines = append(lines, "headscale serves no TLS and listens on "+s.ListenAddr+
			"; the proxy in front terminates TLS for "+wireguard.URLHost(s.ServerURL)+".")
	}
	// The base domain was checked against this server_url already; what is
	// left to warn about is the URL on its own.
	if warning := wireguard.ServerURLWarning(s.ServerURL,
		a.state.Headscale.ControlPlane.OIDC.Configured()); warning != "" {
		lines = append(lines, "WARNING: "+warning)
	}
	lines = append(lines, "", "Step 1 of 2 — rewrite "+wireguard.HeadscaleConfigPath+
		". Only the lines below change; everything else in the file, comments included, "+
		"is kept byte for byte.")
	return strings.Join(lines, "\n")
}
