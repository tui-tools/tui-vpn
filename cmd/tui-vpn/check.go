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
	Present        bool   `json:"present"`
	Error          string `json:"error,omitempty"`
	OIDCConfigured bool   `json:"oidcConfigured"`
	Users          int    `json:"users"`
	Nodes          int    `json:"nodes"`
	NodesOnline    int    `json:"nodesOnline"`
	NodesExpired   int    `json:"nodesExpired"`
	PreAuthKeys    int    `json:"preAuthKeys"`
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
	summary := hsSummary{
		Present:        hs.Present,
		Error:          hs.Error,
		OIDCConfigured: hs.OIDCConfigured,
		Users:          len(hs.Users),
		Nodes:          len(hs.Nodes),
		PreAuthKeys:    len(hs.PreAuthKeys),
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
