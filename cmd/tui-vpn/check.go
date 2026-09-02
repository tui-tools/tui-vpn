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
	Available  bool           `json:"available"`
	Error      string         `json:"error,omitempty"`
	Interfaces []ifaceSummary `json:"interfaces"`
}

// ifaceSummary is one interface without anything that identifies it on the wire.
type ifaceSummary struct {
	Name          string        `json:"name"`
	Up            bool          `json:"up"`
	ListenPort    int           `json:"listenPort"`
	HasPrivateKey bool          `json:"hasPrivateKey"`
	PeerCount     int           `json:"peerCount"`
	Peers         []peerSummary `json:"peers"`
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
}

// cpSummary is what /etc/headscale/config.yaml says, reduced to the facts a
// support answer needs.
type cpSummary struct {
	ConfigPath   string `json:"configPath"`
	Readable     bool   `json:"readable"`
	Error        string `json:"error,omitempty"`
	ServiceState string `json:"serviceState,omitempty"`
	// ServerURLSet reports that a server_url is configured at all.
	ServerURLSet bool `json:"serverUrlSet"`
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
}

// runCheck reads the state once and prints the reduced summary as JSON.
func runCheck(ctx context.Context, backend wireguard.Backend,
	backends []compat.Result, out io.Writer) error {
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

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// summariseWG reduces the WireGuard side to counts and ages.
func summariseWG(state wireguard.State) wgSummary {
	now := time.Now()
	summary := wgSummary{Available: state.WGAvailable, Error: state.WGError}
	for _, dev := range state.Devices {
		iface := ifaceSummary{
			Name:          dev.Name,
			Up:            dev.Up,
			ListenPort:    dev.ListenPort,
			HasPrivateKey: dev.HasPrivateKey,
			PeerCount:     len(dev.Peers),
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
		OIDCConfigured: hs.OIDCEnabled(),
		OIDCInferred:   hs.OIDCInferred,
		OIDCIssuer:     wireguard.URLHost(cp.OIDC.Issuer),
		ControlPlane: cpSummary{
			ConfigPath:             cp.ConfigPath,
			Readable:               cp.Readable,
			Error:                  cp.Error,
			ServiceState:           cp.ServiceState,
			ServerURLSet:           cp.ServerURL != "",
			ServerURLHTTPS:         wireguard.ServerURLIsHTTPS(cp.ServerURL),
			ServerURLLoopback:      wireguard.IsLoopbackHost(wireguard.URLHost(cp.ServerURL)),
			ServerURLWarning:       wireguard.ServerURLWarning(cp.ServerURL),
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
	for _, node := range hs.Nodes {
		if node.Online {
			summary.NodesOnline++
		}
		if !node.Expiry.IsZero() && node.Expiry.Before(now) {
			summary.NodesExpired++
		}
	}
	return summary
}

// handshakeAge is seconds since a handshake, or -1 when there has never been
// one.
func handshakeAge(now, t time.Time) int {
	if t.IsZero() {
		return -1
	}
	return int(now.Sub(t).Seconds())
}
