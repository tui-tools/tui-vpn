package wireguard

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/tui-tools/tui-kit/runner"
)

// Fake is the in-memory backend behind --demo and the tests. It previews
// exactly the commands the real backend would, then applies them to its own
// state instead of to the machine, so the UI cannot tell it from the real
// thing and a test can assert that the command that ran is the command the
// preview showed.
//
// Every key in here is an obviously invented placeholder and every address is
// from a documentation range, enforced by the tests: the demo has to run with
// nothing installed and leak nothing about the host it runs on.
type Fake struct {
	mu    sync.Mutex
	state State
	run   *runner.Fake
}

// Demonstration keys. They are valid WireGuard key syntax (43 base64 characters
// and a '=') but plainly not real: a run of one letter could not be a key any
// tool generated.
const (
	demoIfacePub = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	demoPeer1Pub = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
	demoPeer2Pub = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
)

// DemoIfacePub, DemoPeer1Pub and DemoPeer2Pub expose the placeholder public
// keys the demo uses, so tests can assert they never leak into a report.
func DemoIfacePub() string { return demoIfacePub }
func DemoPeer1Pub() string { return demoPeer1Pub }
func DemoPeer2Pub() string { return demoPeer2Pub }

// NewFake returns a Fake preloaded with a plausible network: one interface with
// two peers — one mid-handshake, one that has never connected — and a Headscale
// control plane with two users, three nodes and a pre-auth key.
func NewFake() *Fake {
	f := &Fake{state: demoState()}
	f.run = &runner.Fake{Hook: f.apply}
	return f
}

// Name identifies the backend.
func (f *Fake) Name() string { return "demo" }

// Describe is the one-line summary shown in the header.
func (f *Fake) Describe() string {
	return "wireguard + headscale  ·  demo (no changes are applied)"
}

// Preview renders the command the way the real backend would.
func (f *Fake) Preview(cmd runner.Command) string { return f.run.Preview(cmd) }

// Run applies a confirmed command to the in-memory state.
func (f *Fake) Run(ctx context.Context, cmd runner.Command) (string, error) {
	return f.run.Run(ctx, cmd)
}

// Commands returns every command the fake was asked to run, for the tests.
func (f *Fake) Commands() []runner.Command { return f.run.Ran }

// Load returns a copy of the sample state.
func (f *Fake) Load(_ context.Context) (State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state, nil
}

// apply mutates the sample state the way the real command would. It is the
// runner.Fake hook, so it runs only for a command that was previewed and
// confirmed — the same path the real backend takes.
func (f *Fake) apply(cmd runner.Command) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	argv := cmd.Argv
	switch {
	case len(argv) == 3 && argv[0] == "wg-quick" && argv[1] == "up":
		return f.setUp(argv[2], true)
	case len(argv) == 3 && argv[0] == "wg-quick" && argv[1] == "down":
		return f.setUp(argv[2], false)
	case len(argv) >= 6 && argv[0] == "wg" && argv[1] == "set" && argv[3] == "peer" && argv[5] == "remove":
		return f.removePeer(argv[2], argv[4])
	case len(argv) >= 7 && argv[0] == "wg" && argv[1] == "set" && argv[3] == "peer" && argv[5] == "allowed-ips":
		return f.addPeer(argv[2], argv[4], strings.Split(argv[6], ","))
	case len(argv) == 5 && argv[0] == "headscale" && argv[1] == "nodes" && argv[2] == "expire":
		return f.expireNode(argv[4])
	case len(argv) == 4 && argv[0] == "headscale" && argv[1] == "users" && argv[2] == "create":
		return f.createUser(argv[3])
	default:
		return "", fmt.Errorf("demo backend does not know how to apply %q", cmd.String())
	}
}

func (f *Fake) setUp(iface string, up bool) (string, error) {
	for i := range f.state.Devices {
		if f.state.Devices[i].Name == iface {
			f.state.Devices[i].Up = up
			if up {
				return "[#] interface " + iface + " up", nil
			}
			return "[#] interface " + iface + " down", nil
		}
	}
	return "", fmt.Errorf("no such interface: %s", iface)
}

func (f *Fake) removePeer(iface, key string) (string, error) {
	for i := range f.state.Devices {
		if f.state.Devices[i].Name != iface {
			continue
		}
		peers := f.state.Devices[i].Peers
		for j := range peers {
			if peers[j].PublicKey == key {
				f.state.Devices[i].Peers = append(peers[:j], peers[j+1:]...)
				return "", nil
			}
		}
	}
	return "", fmt.Errorf("no such peer on %s", iface)
}

func (f *Fake) addPeer(iface, key string, ips []string) (string, error) {
	for i := range f.state.Devices {
		if f.state.Devices[i].Name == iface {
			f.state.Devices[i].Peers = append(f.state.Devices[i].Peers, Peer{
				PublicKey:  key,
				AllowedIPs: ips,
			})
			return "", nil
		}
	}
	return "", fmt.Errorf("no such interface: %s", iface)
}

func (f *Fake) expireNode(id string) (string, error) {
	for i := range f.state.Headscale.Nodes {
		if f.state.Headscale.Nodes[i].ID == id {
			f.state.Headscale.Nodes[i].Expiry = time.Now().Add(-time.Minute)
			f.state.Headscale.Nodes[i].Online = false
			return "Node expired", nil
		}
	}
	return "", fmt.Errorf("no such node: %s", id)
}

func (f *Fake) createUser(name string) (string, error) {
	for _, u := range f.state.Headscale.Users {
		if u.Name == name {
			return "", fmt.Errorf("user %q already exists", name)
		}
	}
	next := fmt.Sprintf("%d", len(f.state.Headscale.Users)+1)
	f.state.Headscale.Users = append(f.state.Headscale.Users, User{
		ID: next, Name: name, CreatedAt: time.Now(),
	})
	return "User created", nil
}

// demoState is the sample network. Times are relative to now, so the view reads
// sensibly however long after this was written it runs.
func demoState() State {
	now := time.Now()
	return State{
		WGAvailable: true,
		Devices: []Device{{
			Name:          "wg0",
			PublicKey:     demoIfacePub,
			HasPrivateKey: true,
			ListenPort:    51820,
			FwMark:        "off",
			Up:            true,
			Peers: []Peer{
				{
					// Mid-handshake: connected seconds ago, moving bytes.
					PublicKey:       demoPeer1Pub,
					HasPresharedKey: true,
					Endpoint:        "198.51.100.10:51820",
					AllowedIPs:      []string{"192.0.2.2/32"},
					LastHandshake:   now.Add(-42 * time.Second),
					RxBytes:         8_452_112,
					TxBytes:         3_221_004,
					Keepalive:       25,
				},
				{
					// Configured but never connected.
					PublicKey:     demoPeer2Pub,
					Endpoint:      "",
					AllowedIPs:    []string{"192.0.2.3/32", "2001:db8::3/128"},
					LastHandshake: time.Time{},
				},
			},
		}},
		Headscale: Headscale{
			Present:        true,
			OIDCConfigured: true,
			Users: []User{
				{ID: "1", Name: "ana", DisplayName: "Ana Ba", Email: "ana@example.com",
					Provider: "oidc", ProviderID: "https://idp.example.com/ana",
					CreatedAt: now.Add(-30 * 24 * time.Hour)},
				{ID: "2", Name: "bo", DisplayName: "Bo Cee", Email: "bo@example.com",
					Provider: "oidc", ProviderID: "https://idp.example.com/bo",
					CreatedAt: now.Add(-12 * 24 * time.Hour)},
			},
			Nodes: []Node{
				{ID: "1", Name: "ana-laptop", GivenName: "ana-laptop", User: "ana",
					IPAddresses: []string{"192.0.2.2", "2001:db8::2"},
					LastSeen:    now.Add(-42 * time.Second), Online: true,
					RegisterMethod: "REGISTER_METHOD_OIDC",
					Expiry:         now.Add(150 * 24 * time.Hour)},
				{ID: "2", Name: "bo-phone", GivenName: "bo-phone", User: "bo",
					IPAddresses: []string{"192.0.2.3"},
					LastSeen:    now.Add(-6 * time.Hour), Online: false,
					RegisterMethod: "REGISTER_METHOD_OIDC",
					Expiry:         now.Add(150 * 24 * time.Hour)},
				{ID: "3", Name: "ci-runner", GivenName: "ci-runner", User: "ana",
					IPAddresses: []string{"192.0.2.4"},
					LastSeen:    now.Add(-3 * 24 * time.Hour), Online: false,
					RegisterMethod: "REGISTER_METHOD_AUTH_KEY",
					// Already expired: the row the operator is meant to notice.
					Expiry: now.Add(-2 * 24 * time.Hour)},
			},
			PreAuthKeys: []PreAuthKey{
				{ID: "1", User: "ana", KeyPrefix: "0123456789", Reusable: true,
					Ephemeral: false, Used: false,
					Expiration: now.Add(24 * time.Hour),
					CreatedAt:  now.Add(-2 * time.Hour),
					ACLTags:    []string{"tag:ci"}},
			},
		},
	}
}
