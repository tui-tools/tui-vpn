package main

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-vpn/internal/wireguard"
)

// checkTimeout bounds the whole read.
const checkTimeout = 30 * time.Second

// checkReport is what --check prints: one read of the interfaces and the
// control plane, reduced to counts and ages.
//
// PRIVACY: this block is meant to be pasted into scripts and issues, so it
// carries no public key, no endpoint and no address of this host — only how
// many of each thing there are and how long ago each peer last shook hands.
//
// The control-plane block keeps that promise too, which took a second pass to
// get right. An "OIDC does not work" report needs to know whether server_url
// is https and whether it points at loopback — those are the two failures — but
// it does not need the URL, which names this host. So the two questions are
// answered as booleans and the URL stays here. The OIDC issuer is reduced to
// its host: enough to say which IdP, without the realm and path that describe
// somebody's internal layout. The allow lists are counted rather than printed,
// because they name people, and the client secret has no field at all, only
// the fact that one is set.
type checkReport struct {
	Tool     string `json:"tool"`
	Version  string `json:"version"`
	Backend  string `json:"backend"`
	Describe string `json:"describe"`

	WireGuard wgSummary `json:"wireguard"`
	Headscale hsSummary `json:"headscale"`

	// Compat is what the version probe found, one entry per backend declared.
	Compat []compat.Result `json:"compat"`
}

// wgSummary is the WireGuard side, reduced.
type wgSummary struct {
	Available bool   `json:"available"`
	Error     string `json:"error,omitempty"`
	// FirewallChecked reports that the host firewall (`iptables -S`) was
	// read; without root it is not, and every listenPortInput is "unknown".
	FirewallChecked bool           `json:"firewallChecked"`
	Interfaces      []ifaceSummary `json:"interfaces"`
}

// ifaceSummary is one interface without anything that identifies it on the wire.
type ifaceSummary struct {
	Name          string        `json:"name"`
	Up            bool          `json:"up"`
	ListenPort    int           `json:"listenPort"`
	HasPrivateKey bool          `json:"hasPrivateKey"`
	PeerCount     int           `json:"peerCount"`
	Peers         []peerSummary `json:"peers"`
	// ListenPortInput is what the host's INPUT chain does with a handshake
	// to the listen port: accept, reject, drop, or unknown when the ruleset
	// could not be read.
	ListenPortInput wireguard.Verdict `json:"listenPortInput"`
	// Forwarding is whether the host's FORWARD chain accepts traffic in on
	// this interface: a forwarding server.
	Forwarding bool `json:"forwarding"`
}

// peerSummary is one peer's health, with no key and no endpoint.
type peerSummary struct {
	// LastHandshakeAgeSeconds is how long ago the peer last shook hands, or -1
	// when it never has.
	LastHandshakeAgeSeconds int  `json:"lastHandshakeAgeSeconds"`
	AllowedIPCount          int  `json:"allowedIpCount"`
	HasPresharedKey         bool `json:"hasPresharedKey"`
	KeepaliveSeconds        int  `json:"keepaliveSeconds"`
}

// hsSummary is the control-plane side, reduced to counts.
type hsSummary struct {
	Present bool   `json:"present"`
	Error   string `json:"error,omitempty"`
	// NotRunning reports that the lists were not read because the headscale
	// unit is stopped; Error then says how to start it.
	NotRunning bool `json:"notRunning,omitempty"`
	// OIDCConfigured is read from headscale's configuration: an issuer and a
	// client id are what make identity federated.
	OIDCConfigured bool `json:"oidcConfigured"`
	// OIDCInferred is the older, weaker answer — guessed from who has logged
	// in — kept as the fallback for a host whose config.yaml cannot be read.
	OIDCInferred bool `json:"oidcInferred"`
	// OIDCIssuer is the HOST of the IdP the control plane federates to, never
	// the whole issuer URL.
	OIDCIssuer   string    `json:"oidcIssuer,omitempty"`
	ControlPlane cpSummary `json:"controlPlane"`
	Users        int       `json:"users"`
	Nodes        int       `json:"nodes"`
	NodesOnline  int       `json:"nodesOnline"`
	NodesExpired int       `json:"nodesExpired"`
	PreAuthKeys  int       `json:"preAuthKeys"`
	// NodeRoutes is each node's routes, counted: advertised, approved (and
	// advertised), pending approval, and where it stands as an exit node. The
	// CIDRs themselves are not printed: they are the networks behind the
	// tailnet, which is as much an address of somebody's layout as the
	// endpoints --check leaves out.
	NodeRoutes []nodeRoutes `json:"nodeRoutes,omitempty"`
}

// nodeRoutes is one node's routes, reduced to counts.
type nodeRoutes struct {
	ID         string `json:"id"`
	Advertised int    `json:"advertised"`
	Approved   int    `json:"approved"`
	Pending    int    `json:"pending"`
	// ExitNode is "" (not advertised), "pending" or "approved".
	ExitNode string `json:"exitNode,omitempty"`
}

// cpSummary is what /etc/headscale/config.yaml says, reduced to the facts a
// support answer needs.
type cpSummary struct {
	ConfigPath   string `json:"configPath"`
	Readable     bool   `json:"readable"`
	Error        string `json:"error,omitempty"`
	ServiceState string `json:"serviceState,omitempty"`
	// ServiceEnabled is `systemctl is-enabled headscale`: "disabled" is the
	// fresh-install state that loses the control plane at the next reboot.
	ServiceEnabled string `json:"serviceEnabled,omitempty"`
	// ServiceAccount is who the unit runs as, user:group.
	ServiceAccount string `json:"serviceAccount,omitempty"`
	// OwnershipChecked and OwnershipOK answer whether headscale can read its
	// own state and the files this tool writes for it; OwnershipIssues names
	// each path that is owned by the wrong account. The paths are the
	// packaged defaults or what config.yaml names for headscale's state, not
	// anything that locates this host.
	OwnershipChecked bool                       `json:"ownershipChecked"`
	OwnershipOK      bool                       `json:"ownershipOk"`
	OwnershipIssues  []wireguard.OwnershipIssue `json:"ownershipIssues,omitempty"`
	// ServerURLSet reports that a server_url is configured at all, and
	// ServerURLValid that its host is an address that parses or a DNS name
	// (a mistyped IP such as 203.0.113.1000 is neither).
	ServerURLSet   bool `json:"serverUrlSet"`
	ServerURLValid bool `json:"serverUrlValid"`
	// ServerURLHTTPS and ServerURLLoopback are what the URL itself is not
	// printed for: whether it is https, which most IdPs require of a redirect
	// target, and whether it points at loopback, which no client's browser can
	// reach. Those are the two ways an otherwise healthy setup fails, and
	// answering them as booleans says nothing about where this host lives.
	ServerURLHTTPS    bool `json:"serverUrlHttps"`
	ServerURLLoopback bool `json:"serverUrlLoopback"`
	// ServerURLWarning names the reason a browser-based OIDC login cannot work
	// against this server_url, when there is one. It is a fixed explanation
	// and never quotes the URL.
	ServerURLWarning string `json:"serverUrlWarning,omitempty"`
	// ServerURLIsIP reports a server_url addressed by IP rather than by name:
	// fine over plain http, and the reason Let's Encrypt is not an option.
	ServerURLIsIP bool `json:"serverUrlIsIp"`
	// Transport is how clients reach headscale: plain-http, letsencrypt,
	// own-cert or reverse-proxy, read from the TLS settings and the bind.
	Transport wireguard.Transport `json:"transport,omitempty"`
	// BaseDomain is dns.base_domain, the MagicDNS suffix nodes are named
	// under. It is the tailnet's own naming, printed like the issuer's host;
	// BaseDomainConflict is the startup failure headscale reports when the
	// server_url host sits inside it.
	BaseDomain         string `json:"baseDomain,omitempty"`
	BaseDomainConflict bool   `json:"baseDomainConflict"`
	MagicDNS           bool   `json:"magicDns"`
	// ListenPort and ListenLoopback replace listen_addr for the same reason:
	// a bind address can name an internal interface of this machine, while
	// the port and "is it only listening to itself" are the useful halves.
	ListenPort     int  `json:"listenPort"`
	ListenLoopback bool `json:"listenLoopback"`
	// OIDCIssuer is the issuer's HOST, not the issuer URL: which IdP, without
	// the realm and path that describe somebody's internal layout.
	OIDCIssuer   string `json:"oidcIssuer,omitempty"`
	OIDCClientID string `json:"oidcClientId,omitempty"`
	// OIDCClientSecretSet reports that a secret is configured, never what it
	// is; OIDCClientSecretInline reports the case worth fixing, where it sits
	// in config.yaml instead of its own root-only file.
	OIDCClientSecretSet    bool `json:"oidcClientSecretSet"`
	OIDCClientSecretInline bool `json:"oidcClientSecretInline,omitempty"`
	// The allow lists are counted, not printed: they name people.
	AllowedDomains int      `json:"allowedDomains"`
	AllowedGroups  int      `json:"allowedGroups"`
	AllowedUsers   int      `json:"allowedUsers"`
	Scope          []string `json:"scope,omitempty"`
	OnlyStart      bool     `json:"onlyStartIfOidcIsAvailable"`
	PKCE           bool     `json:"pkce"`
	// OIDCReadiness answers "will a browser login work" as facts: the
	// redirect URI's shape, whether any allow list restricts access, and the
	// two allow-list mistakes headscale makes silently. It is present when
	// OIDC is configured. issuerReachable is only in it with --probe-issuer:
	// a plain --check never goes on the network.
	OIDCReadiness *wireguard.OIDCReadiness `json:"oidcReadiness,omitempty"`
}

// checkOptions are the --check switches beyond the plain read.
type checkOptions struct {
	// probeIssuer asks for the issuer's discovery document to be fetched
	// from this machine, the one network request --check can make.
	probeIssuer bool
}

// runCheck reads the state once and prints the reduced summary as JSON.
func runCheck(ctx context.Context, backend wireguard.Backend,
	backends []compat.Result, out io.Writer) error {
	return runCheckWith(ctx, backend, backends, out, checkOptions{})
}

// runCheckWith is runCheck with the optional switches.
func runCheckWith(ctx context.Context, backend wireguard.Backend,
	backends []compat.Result, out io.Writer, opts checkOptions) error {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()

	state, err := backend.Load(ctx)
	if err != nil {
		return err
	}

	report := checkReport{
		Tool:      toolName,
		Version:   version,
		Backend:   backend.Name(),
		Describe:  backend.Describe(),
		WireGuard: summariseWG(state),
		Headscale: summariseHS(state.Headscale),
		Compat:    backends,
	}
	if readiness := report.Headscale.ControlPlane.OIDCReadiness; readiness != nil &&
		opts.probeIssuer {
		reachable := probeIssuer(ctx, backend, state.Headscale.ControlPlane.OIDC.Issuer)
		readiness.IssuerReachable = &reachable
	}

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// summariseWG reduces the WireGuard side to counts and ages.
func summariseWG(state wireguard.State) wgSummary {
	now := time.Now()
	summary := wgSummary{Available: state.WGAvailable, Error: state.WGError,
		FirewallChecked: state.Firewall.Checked}
	for _, dev := range state.Devices {
		verdict := dev.PortVerdict
		if verdict == "" {
			verdict = wireguard.VerdictUnknown
		}
		iface := ifaceSummary{
			Name:            dev.Name,
			Up:              dev.Up,
			ListenPort:      dev.ListenPort,
			HasPrivateKey:   dev.HasPrivateKey,
			PeerCount:       len(dev.Peers),
			ListenPortInput: verdict,
			Forwarding:      dev.Forwarding,
		}
		for _, peer := range dev.Peers {
			iface.Peers = append(iface.Peers, peerSummary{
				LastHandshakeAgeSeconds: handshakeAge(now, peer.LastHandshake),
				AllowedIPCount:          len(peer.AllowedIPs),
				HasPresharedKey:         peer.HasPresharedKey,
				KeepaliveSeconds:        peer.Keepalive,
			})
		}
		summary.Interfaces = append(summary.Interfaces, iface)
	}
	return summary
}

// summariseHS reduces the control plane to counts.
func summariseHS(hs wireguard.Headscale) hsSummary {
	now := time.Now()
	cp := hs.ControlPlane
	summary := hsSummary{
		Present:        hs.Present,
		Error:          hs.Error,
		NotRunning:     hs.NotRunning,
		OIDCConfigured: hs.OIDCEnabled(),
		OIDCInferred:   hs.OIDCInferred,
		OIDCIssuer:     wireguard.URLHost(cp.OIDC.Issuer),
		ControlPlane: cpSummary{
			ConfigPath:             cp.ConfigPath,
			Readable:               cp.Readable,
			Error:                  cp.Error,
			ServiceState:           cp.ServiceState,
			ServiceEnabled:         cp.ServiceEnabled,
			ServiceAccount:         serviceAccountOf(cp),
			OwnershipChecked:       cp.Ownership.Checked,
			OwnershipOK:            cp.Ownership.OK(),
			OwnershipIssues:        cp.Ownership.Issues,
			ServerURLSet:           cp.ServerURL != "",
			ServerURLValid:         wireguard.ValidServerURL(cp.ServerURL),
			ServerURLHTTPS:         wireguard.ServerURLIsHTTPS(cp.ServerURL),
			ServerURLLoopback:      wireguard.IsLoopbackHost(wireguard.URLHost(cp.ServerURL)),
			ServerURLWarning:       wireguard.ServerURLWarning(cp.ServerURL, cp.OIDC.Configured()),
			ServerURLIsIP:          wireguard.IsIPHost(wireguard.URLHost(cp.ServerURL)),
			Transport:              transportOf(cp),
			BaseDomain:             cp.BaseDomain,
			BaseDomainConflict:     wireguard.BaseDomainConflict(cp.ServerURL, cp.BaseDomain) != "",
			MagicDNS:               cp.MagicDNS,
			ListenPort:             wireguard.ListenPort(cp.ListenAddr),
			ListenLoopback:         wireguard.IsLoopbackHost(wireguard.ListenHost(cp.ListenAddr)),
			OIDCIssuer:             wireguard.URLHost(cp.OIDC.Issuer),
			OIDCClientID:           cp.OIDC.ClientID,
			OIDCClientSecretSet:    cp.OIDC.ClientSecretSet,
			OIDCClientSecretInline: cp.OIDC.ClientSecretInline,
			AllowedDomains:         len(cp.OIDC.AllowedDomains),
			AllowedGroups:          len(cp.OIDC.AllowedGroups),
			AllowedUsers:           len(cp.OIDC.AllowedUsers),
			Scope:                  cp.OIDC.Scope,
			OnlyStart:              cp.OIDC.OnlyStartIfAvailable,
			PKCE:                   cp.OIDC.PKCE,
		},
		Users:       len(hs.Users),
		Nodes:       len(hs.Nodes),
		PreAuthKeys: len(hs.PreAuthKeys),
	}
	if cp.Readable && cp.OIDC.Configured() {
		readiness := wireguard.ReadinessOf(cp)
		summary.ControlPlane.OIDCReadiness = &readiness
	}
	for _, node := range hs.Nodes {
		if routes := routesOf(node); routes != nil {
			summary.NodeRoutes = append(summary.NodeRoutes, *routes)
		}
		if node.Online {
			summary.NodesOnline++
		}
		if !node.Expiry.IsZero() && node.Expiry.Before(now) {
			summary.NodesExpired++
		}
	}
	return summary
}

// probeIssuer fetches the issuer's discovery document from this machine, the
// same read O makes before saving, and reports whether it answered like an
// OpenID Provider.
func probeIssuer(ctx context.Context, backend wireguard.Backend, issuer string) bool {
	cmd, err := wireguard.BuildDiscoverIssuer(issuer)
	if err != nil {
		return false
	}
	out, err := backend.Run(ctx, cmd)
	return err == nil && wireguard.DiscoveryLooksValid(out)
}

// routesOf counts a node's routes, or nil when it has none: most nodes are
// plain clients and would only add noise. The exit routes count as one.
func routesOf(n wireguard.Node) *nodeRoutes {
	states := wireguard.NodeRoutes(n)
	if len(states) == 0 {
		return nil
	}
	r := &nodeRoutes{ID: n.ID, ExitNode: wireguard.ExitNodeState(n)}
	for _, st := range states {
		if wireguard.IsExitRoute(st.Route) || !st.Advertised {
			continue
		}
		r.Advertised++
		if st.Approved {
			r.Approved++
		} else {
			r.Pending++
		}
	}
	return r
}

// handshakeAge is seconds since a handshake, or -1 when there has never been
// one.
func handshakeAge(now, t time.Time) int {
	if t.IsZero() {
		return -1
	}
	return int(now.Sub(t).Seconds())
}

// transportOf is the transport for --check, empty when config.yaml could not
// be read: an unread configuration has no transport to report, and the empty
// one would read as plain http.
func transportOf(cp wireguard.ControlPlane) wireguard.Transport {
	if !cp.Readable {
		return ""
	}
	return wireguard.DetectTransport(cp)
}

// serviceAccountOf is the unit's account for --check, empty when it was not
// read (an unreadable configuration never gets that far).
func serviceAccountOf(cp wireguard.ControlPlane) string {
	if cp.ServiceUser == "" {
		return ""
	}
	return serviceAccount(cp)
}
