// Package wireguard is the part of tui-vpn that is about its own subject:
// WireGuard interfaces and their peers, and — when a Headscale control plane
// is present — the users, nodes and pre-authentication keys that decide who is
// allowed onto the network. Everything generic (palette, widgets,
// configuration, running commands) comes from tui-kit and is not repeated here.
//
// This package is also the tool's single exec site: the only place a process
// is started (through the kit runner) is internal/wireguard, so the command
// the confirm dialog showed is provably the command that ran. It drives four
// programs — `wg`, `wg-quick`, `headscale` and read-only `ip` — but every one
// of them goes through the same runner boundary.
//
// PRIVACY: a private key never leaves this package on an argv or in any
// rendered value. Adding a peer needs only its public key; a pre-shared key is
// passed to `wg set` as a file path, never as a value on the command line
// (a command line is visible in `ps` to every user on the machine). The model
// records whether an interface has a private key, never the key itself.
package wireguard

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/tui-tools/tui-kit/runner"
)

// Screen is one of the five views the tool is made of. They are tabs because
// they answer five separate questions: what is my WireGuard doing, who are its
// peers, and — on the control plane — who exists, what is registered, and what
// can still join.
type Screen int

const (
	// ScreenStatus lists the WireGuard interfaces on this host.
	ScreenStatus Screen = iota
	// ScreenPeers lists the peers of the selected interface.
	ScreenPeers
	// ScreenUsers lists the Headscale users.
	ScreenUsers
	// ScreenNodes lists the Headscale nodes.
	ScreenNodes
	// ScreenKeys lists the Headscale pre-authentication keys.
	ScreenKeys
	// ScreenCount is the number of screens: it drives the tab bar and the
	// per-screen cursor arrays.
	ScreenCount
)

// Title is the tab label.
func (s Screen) Title() string {
	switch s {
	case ScreenPeers:
		return "peers"
	case ScreenUsers:
		return "users"
	case ScreenNodes:
		return "nodes"
	case ScreenKeys:
		return "preauth keys"
	default:
		return "interfaces"
	}
}

// Device is one WireGuard interface. It never carries the private key: the most
// a running tool needs to know is that one is configured.
type Device struct {
	Name string `json:"name"`
	// PublicKey is the interface's own public key. It is safe to show.
	PublicKey string `json:"publicKey"`
	// HasPrivateKey reports that a private key is configured, without being it.
	HasPrivateKey bool `json:"hasPrivateKey"`
	// ListenPort is the UDP port the interface listens on, 0 when unset.
	ListenPort int `json:"listenPort"`
	// FwMark is the firewall mark, "off" when unset.
	FwMark string `json:"fwMark,omitempty"`
	// Up reports whether the link is up, as `ip link` sees it.
	Up    bool   `json:"up"`
	Peers []Peer `json:"peers"`
}

// Peer is one entry under an interface.
type Peer struct {
	// PublicKey identifies the peer. It is safe to show.
	PublicKey string `json:"publicKey"`
	// HasPresharedKey reports that a pre-shared key is set, without being it.
	HasPresharedKey bool `json:"hasPresharedKey"`
	// Endpoint is the peer's ip:port, empty when it has never connected.
	Endpoint string `json:"endpoint,omitempty"`
	// AllowedIPs is the set of prefixes routed to this peer.
	AllowedIPs []string `json:"allowedIPs"`
	// LastHandshake is when the peer last completed a handshake; zero = never.
	LastHandshake time.Time `json:"lastHandshake,omitempty"`
	// RxBytes and TxBytes are the counters since the interface came up.
	RxBytes int64 `json:"rxBytes"`
	TxBytes int64 `json:"txBytes"`
	// Keepalive is the persistent-keepalive interval in seconds, 0 = off.
	Keepalive int `json:"keepalive"`
}

// Headscale is the state of the control plane, when one is reachable.
type Headscale struct {
	// Present reports that the headscale binary was found and answered.
	Present bool `json:"present"`
	// Error carries why a present control plane could not be read.
	Error string `json:"error,omitempty"`
	// OIDCConfigured reports that user identity comes from an external
	// OpenID Connect provider — inferred from a user carrying a provider, or a
	// node that registered through OIDC. This is the whole point of the design:
	// login happens in the client's browser against the IdP, and the server
	// exposes no web admin of its own.
	OIDCConfigured bool         `json:"oidcConfigured"`
	Users          []User       `json:"users"`
	Nodes          []Node       `json:"nodes"`
	PreAuthKeys    []PreAuthKey `json:"preAuthKeys"`
}

// User is a Headscale user. Its identity, when OIDC is configured, is owned by
// the IdP; headscale only mirrors it.
type User struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"displayName,omitempty"`
	Email       string    `json:"email,omitempty"`
	Provider    string    `json:"provider,omitempty"`
	ProviderID  string    `json:"providerId,omitempty"`
	CreatedAt   time.Time `json:"createdAt,omitempty"`
}

// Node is a machine registered with Headscale, owned by one user.
type Node struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	GivenName      string    `json:"givenName,omitempty"`
	User           string    `json:"user"`
	IPAddresses    []string  `json:"ipAddresses"`
	LastSeen       time.Time `json:"lastSeen,omitempty"`
	Expiry         time.Time `json:"expiry,omitempty"`
	Online         bool      `json:"online"`
	RegisterMethod string    `json:"registerMethod,omitempty"`
}

// PreAuthKey is a key that lets a machine register itself for a user without a
// browser login. Headscale only ever shows its prefix on a list, never the
// whole key, and neither do we.
type PreAuthKey struct {
	ID         string    `json:"id"`
	User       string    `json:"user"`
	KeyPrefix  string    `json:"keyPrefix,omitempty"`
	Reusable   bool      `json:"reusable"`
	Ephemeral  bool      `json:"ephemeral"`
	Used       bool      `json:"used"`
	Expiration time.Time `json:"expiration,omitempty"`
	CreatedAt  time.Time `json:"createdAt,omitempty"`
	ACLTags    []string  `json:"aclTags,omitempty"`
}

// State is everything one read produces: the WireGuard side and the control
// plane side, each able to be empty without the other failing.
type State struct {
	// WGAvailable reports that the wg binary was found.
	WGAvailable bool `json:"wgAvailable"`
	// WGError carries why an available wg could not be read (usually: no
	// privilege). It is not fatal — the control plane may still have answers.
	WGError string   `json:"wgError,omitempty"`
	Devices []Device `json:"devices"`

	Headscale Headscale `json:"headscale"`
}

// Device returns the interface by name.
func (s State) Device(name string) (Device, bool) {
	for _, d := range s.Devices {
		if d.Name == name {
			return d, true
		}
	}
	return Device{}, false
}

// Action is something the user can do. Each maps to one previewed command.
type Action string

const (
	// ActionInterfaceUp brings an interface up with wg-quick.
	ActionInterfaceUp Action = "interface-up"
	// ActionInterfaceDown takes an interface down with wg-quick.
	ActionInterfaceDown Action = "interface-down"
	// ActionRemovePeer removes a peer from an interface.
	ActionRemovePeer Action = "remove-peer"
	// ActionExpireNode expires a Headscale node's key.
	ActionExpireNode Action = "expire-node"
	// ActionCreateUser creates a Headscale user.
	ActionCreateUser Action = "create-user"
)

// keyPattern is a WireGuard key on the wire: 43 base64 characters and a '='.
// Both public and private keys share this shape, which is exactly why the shape
// alone cannot be trusted: the safeguard is that this package only ever accepts
// a parameter named "public key" and never builds a `private-key` argument.
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)

// ValidPublicKey reports whether s is a syntactically valid WireGuard key.
func ValidPublicKey(s string) bool { return keyPattern.MatchString(s) }

// ifacePattern is a plausible network interface name: letters, digits and a
// few separators, nothing that could turn into a second argument or a flag.
var ifacePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}$`)

// ValidInterface reports whether s is a plausible interface name.
func ValidInterface(s string) bool {
	return s != "" && !strings.HasPrefix(s, "-") && ifacePattern.MatchString(s)
}

// BuildInterfaceUp assembles `wg-quick up <iface>`.
func BuildInterfaceUp(iface string) (runner.Command, error) {
	if !ValidInterface(iface) {
		return runner.Command{}, fmt.Errorf("not a valid interface name: %q", iface)
	}
	return runner.Command{
		Argv:        []string{"wg-quick", "up", iface},
		Description: "Bring up " + iface,
	}, nil
}

// BuildInterfaceDown assembles `wg-quick down <iface>`.
func BuildInterfaceDown(iface string) (runner.Command, error) {
	if !ValidInterface(iface) {
		return runner.Command{}, fmt.Errorf("not a valid interface name: %q", iface)
	}
	return runner.Command{
		Argv:        []string{"wg-quick", "down", iface},
		Description: "Bring down " + iface,
		Destructive: true,
	}, nil
}

// BuildRemovePeer assembles `wg set <iface> peer <public-key> remove`.
func BuildRemovePeer(iface, publicKey string) (runner.Command, error) {
	if !ValidInterface(iface) {
		return runner.Command{}, fmt.Errorf("not a valid interface name: %q", iface)
	}
	if !ValidPublicKey(publicKey) {
		return runner.Command{}, fmt.Errorf("not a valid public key")
	}
	return runner.Command{
		Argv:        []string{"wg", "set", iface, "peer", publicKey, "remove"},
		Description: "Remove peer from " + iface,
		Destructive: true,
	}, nil
}

// BuildAddPeer assembles `wg set <iface> peer <public-key> allowed-ips <ips>`,
// with an optional pre-shared key read from a file.
//
// The peer is identified by its PUBLIC key. A pre-shared key, when given, is a
// path to a file `wg` opens itself: it is never a value on the argv, so it can
// never appear in the confirm dialog or in `ps`. A private key has no place in
// this call at all, and the guard below refuses one if it is ever wired in by
// mistake.
func BuildAddPeer(iface, publicKey string, allowedIPs []string, presharedKeyFile string) (runner.Command, error) {
	if !ValidInterface(iface) {
		return runner.Command{}, fmt.Errorf("not a valid interface name: %q", iface)
	}
	if !ValidPublicKey(publicKey) {
		return runner.Command{}, fmt.Errorf("not a valid public key")
	}
	ips := make([]string, 0, len(allowedIPs))
	for _, ip := range allowedIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if !ValidAllowedIP(ip) {
			return runner.Command{}, fmt.Errorf("not a valid allowed-ip: %q", ip)
		}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return runner.Command{}, fmt.Errorf("a peer needs at least one allowed-ip")
	}
	argv := []string{"wg", "set", iface, "peer", publicKey, "allowed-ips", strings.Join(ips, ",")}
	if presharedKeyFile != "" {
		if strings.ContainsAny(presharedKeyFile, " \t\n") {
			return runner.Command{}, fmt.Errorf("not a valid file path for the pre-shared key")
		}
		argv = append(argv, "preshared-key", presharedKeyFile)
	}
	return runner.Command{
		Argv:        argv,
		Description: "Add peer to " + iface,
	}, nil
}

// BuildExpireNode assembles `headscale nodes expire --identifier <id>`.
func BuildExpireNode(nodeID string) (runner.Command, error) {
	if !validID(nodeID) {
		return runner.Command{}, fmt.Errorf("not a valid node id: %q", nodeID)
	}
	return runner.Command{
		Argv:        []string{"headscale", "nodes", "expire", "--identifier", nodeID},
		Description: "Expire node " + nodeID,
		Destructive: true,
	}, nil
}

// BuildCreateUser assembles `headscale users create <name>`.
func BuildCreateUser(name string) (runner.Command, error) {
	name = strings.TrimSpace(name)
	if name == "" || strings.HasPrefix(name, "-") || strings.ContainsAny(name, " \t\n/") {
		return runner.Command{}, fmt.Errorf("not a valid user name: %q", name)
	}
	return runner.Command{
		Argv:        []string{"headscale", "users", "create", name},
		Description: "Create user " + name,
	}, nil
}

// validID reports whether s is a bare non-negative integer id.
func validID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// allowedIPPattern is a CIDR or a bare address: digits, hex, dots, colons and a
// single optional /prefix, nothing that could become a second argument.
var allowedIPPattern = regexp.MustCompile(`^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$`)

// ValidAllowedIP reports whether s is a plausible allowed-ip entry.
func ValidAllowedIP(s string) bool {
	return s != "" && !strings.HasPrefix(s, "-") && allowedIPPattern.MatchString(s)
}

// Backend is the boundary between the UI and the machine. Load reads the model;
// Preview renders the exact command a confirmed action would run; Run executes
// it. Nothing else may start a process.
type Backend interface {
	// Name identifies the backend ("wireguard", "demo").
	Name() string
	// Describe is the one-line summary shown in the header.
	Describe() string
	// Load reads the current state. It never fails as a whole: a missing wg or
	// a missing control plane is a fact in the State, not an error.
	Load(ctx context.Context) (State, error)
	// Preview renders the exact command line Run will execute, routing to the
	// right binary so the privilege prefix shown is the one that will apply.
	Preview(cmd runner.Command) string
	// Run executes a previously previewed command.
	Run(ctx context.Context, cmd runner.Command) (string, error)
}
