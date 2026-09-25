package wireguard

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/tui-tools/tui-kit/runner"
)

// searchPaths gives each binary the absolute fallbacks to try when it is not on
// PATH. wg and wg-quick live in /usr/bin on most distributions; ip is in
// /usr/sbin on systems that still split sbin.
var searchPaths = map[string][]string{
	"wg":       {"/usr/bin/wg", "/bin/wg"},
	"wg-quick": {"/usr/bin/wg-quick", "/bin/wg-quick"},
	"ip":       {"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"},
	// sh and install exist for the interface-bootstrap flow: the key pair is
	// generated inside one root shell so the private key never leaves the exec
	// site, and the conf file arrives on install's stdin so content never
	// rides an argv.
	"sh":      {"/bin/sh", "/usr/bin/sh"},
	"install": {"/usr/bin/install", "/bin/install"},
	// iptables reads the host firewall (is a listen port open, does the host
	// forward for an interface) and opens a listen port when asked.
	"iptables": iptablesSearchPaths,
}

// privilegedRead marks the binaries whose reads need root. Reading a WireGuard
// interface needs CAP_NET_ADMIN; `ip link` and `ip route` are ordinary reads.
var privilegedRead = map[string]bool{
	"wg": true,
	"ip": false,
	// Reading the ruleset needs root: unprivileged, iptables refuses with
	// "you must be root".
	"iptables": true,
}

// installHints tell a user what to install when a binary is missing.
var installHints = map[string]string{
	"wg":       "install wireguard-tools",
	"wg-quick": "install wireguard-tools",
	"ip":       "install iproute2",
	"iptables": "install iptables to read and open the host firewall",
}

// Real is the backend that drives the machine. It is the tool's only exec site:
// every process it starts goes through a kit runner, one per binary, resolved
// on first use. Preview and Run pick the runner by the command's own argv[0],
// so the preview the user confirmed carries the exact privilege prefix that
// binary will really run with.
type Real struct {
	sudo []string

	mu      sync.Mutex
	runners map[string]*runner.Runner
	missing map[string]error
}

// New builds the real backend. It deliberately cannot fail: no single binary's
// absence means "nothing to show", because a host may have WireGuard without
// iptables, or the reverse. A missing binary becomes an empty section, found
// out at read time.
func New(sudoPrefix []string) (*Real, error) {
	return &Real{
		sudo:    sudoPrefix,
		runners: map[string]*runner.Runner{},
		missing: map[string]error{},
	}, nil
}

// Name identifies the backend.
func (r *Real) Name() string { return "wireguard" }

// Describe is the one-line summary shown in the header.
func (r *Real) Describe() string {
	if r.available("wg") {
		return "wireguard"
	}
	return "no backend found — install wireguard-tools, or use --demo"
}

// runnerFor resolves a binary's runner on first use and caches it. A binary
// that cannot be resolved is remembered as missing so it is not probed again.
func (r *Real) runnerFor(bin string) (*runner.Runner, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if run, ok := r.runners[bin]; ok {
		return run, nil
	}
	if err, ok := r.missing[bin]; ok {
		return nil, err
	}
	priv := privilegedRead[bin]
	run, err := runner.New(runner.Options{
		Bin:             bin,
		SearchPaths:     searchPaths[bin],
		SudoPrefix:      r.sudo,
		PrivilegedReads: &priv,
		InstallHint:     installHints[bin],
	})
	if err != nil {
		r.missing[bin] = err
		return nil, err
	}
	r.runners[bin] = run
	return run, nil
}

// available reports whether a binary could be resolved.
func (r *Real) available(bin string) bool {
	_, err := r.runnerFor(bin)
	return err == nil
}

// Preview renders the command the way its binary's runner would, so the
// privilege prefix in the dialog is the real one.
func (r *Real) Preview(cmd runner.Command) string {
	if len(cmd.Argv) == 0 {
		return ""
	}
	run, err := r.runnerFor(cmd.Argv[0])
	if err != nil {
		// The binary is missing; show the honest argv without a prefix.
		return strings.Join(cmd.Argv, " ")
	}
	return run.Preview(cmd)
}

// Run executes a previewed command through its binary's runner.
func (r *Real) Run(ctx context.Context, cmd runner.Command) (string, error) {
	if len(cmd.Argv) == 0 {
		return "", fmt.Errorf("nothing to run")
	}
	run, err := r.runnerFor(cmd.Argv[0])
	if err != nil {
		return "", err
	}
	return run.Run(ctx, cmd)
}

// Load reads the whole model: WireGuard first, then the host network around
// it. Neither a missing binary nor a failed read fails the load — each becomes
// a fact the UI can show.
func (r *Real) Load(ctx context.Context) (State, error) {
	var state State

	if run, err := r.runnerFor("wg"); err == nil {
		state.WGAvailable = true
		dump, err := run.Read(ctx, "wg", "show", "all", "dump")
		if err != nil {
			state.WGError = runner.FirstLine(err.Error())
		} else {
			state.Devices = ParseWgDump(dump)
		}
		r.annotateLinks(ctx, &state)
	}
	r.loadHostNet(ctx, &state)
	return state, nil
}

// loadHostNet reads the routing table and the host firewall. Both are best
// effort: a failed route read proposes nothing, and a failed firewall read
// (usually: no root) leaves every port verdict unknown rather than open.
func (r *Real) loadHostNet(ctx context.Context, state *State) {
	if run, err := r.runnerFor("ip"); err == nil {
		if out, err := run.Read(ctx, "ip", "-j", "route"); err == nil {
			state.Routes, _ = ParseRoutes([]byte(out))
		}
	}
	if run, err := r.runnerFor("iptables"); err != nil {
		state.Firewall = Firewall{Error: runner.FirstLine(err.Error())}
	} else if out, err := run.Read(ctx, "iptables", "-S"); err != nil {
		state.Firewall = Firewall{Error: runner.FirstLine(err.Error())}
	} else {
		state.Firewall = ParseIptablesRules(out)
	}
	state.TUIFirewall = runner.Available("tui-firewall", TUIFirewallSearchPaths...)
	state.annotateFirewall()
}

// annotateLinks corrects each device's Up flag from `ip link`, a read no
// privilege is needed for. A failure here is silent: the dump already implies
// the interface is up, and this only refines it.
func (r *Real) annotateLinks(ctx context.Context, state *State) {
	run, err := r.runnerFor("ip")
	if err != nil {
		return
	}
	out, err := run.Read(ctx, "ip", "-o", "link", "show")
	if err != nil {
		return
	}
	up := parseLinkState(out)
	for i := range state.Devices {
		if flag, ok := up[state.Devices[i].Name]; ok {
			state.Devices[i].Up = flag
		}
	}
}

// HostFact is a set of unprivileged facts about this host, for --report. None
// of it reads a key, an endpoint or an address: it counts WireGuard interfaces.
type HostFact struct {
	// WGInterfaces is the number of wireguard-type links, or -1 when the count
	// could not be taken (no ip, or the read failed).
	WGInterfaces int
}

// HostFacts probes the host without privilege, for the bug-report block. It
// runs `ip -o link show type wireguard`, an ordinary read.
func HostFacts(ctx context.Context, sudoPrefix []string) HostFact {
	fact := HostFact{WGInterfaces: -1}

	priv := false
	if ip, err := runner.New(runner.Options{
		Bin: "ip", SearchPaths: searchPaths["ip"], SudoPrefix: sudoPrefix,
		PrivilegedReads: &priv,
	}); err == nil {
		if out, err := ip.Read(ctx, "ip", "-o", "link", "show", "type", "wireguard"); err == nil {
			fact.WGInterfaces = countLines(out)
		}
	}
	return fact
}

// countLines counts the non-empty lines in s.
func countLines(s string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// parseLinkState reads `ip -o link show` into a name → up map. Each line begins
// with an index and the interface name, and carries the interface flags in
// angle brackets; the UP flag there is what "up" means.
func parseLinkState(out string) map[string]bool {
	state := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// "3: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 ..."
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		name := strings.TrimSuffix(fields[1], ":")
		// A link name can carry an @parent suffix (wg0@if4); drop it.
		if at := strings.IndexByte(name, '@'); at >= 0 {
			name = name[:at]
		}
		flags := fields[2]
		state[name] = strings.Contains(flags, "UP") && !strings.Contains(flags, "DOWN,")
	}
	return state
}
