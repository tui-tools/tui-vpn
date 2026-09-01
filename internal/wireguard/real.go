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
	"wg":        {"/usr/bin/wg", "/bin/wg"},
	"wg-quick":  {"/usr/bin/wg-quick", "/bin/wg-quick"},
	"headscale": {"/usr/bin/headscale", "/usr/local/bin/headscale"},
	"ip":        {"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"},
	// sh and install exist for the interface-bootstrap flow: the key pair is
	// generated inside one root shell so the private key never leaves the exec
	// site, and the conf file arrives on install's stdin so content never
	// rides an argv.
	"sh":      {"/bin/sh", "/usr/bin/sh"},
	"install": {"/usr/bin/install", "/bin/install"},
}

// privilegedRead marks the binaries whose reads need root. Reading a WireGuard
// interface needs CAP_NET_ADMIN, and the Headscale CLI talks to a socket only
// root can open; `ip link` is an ordinary read.
var privilegedRead = map[string]bool{
	"wg":        true,
	"headscale": true,
	"ip":        false,
}

// installHints tell a user what to install when a binary is missing.
var installHints = map[string]string{
	"wg":        "install wireguard-tools",
	"wg-quick":  "install wireguard-tools",
	"headscale": "install headscale, or run without a control plane",
	"ip":        "install iproute2",
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
// absence means "nothing to show", because a host may have WireGuard without a
// control plane, or the reverse. A missing binary becomes an empty section,
// found out at read time.
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
	parts := []string{}
	if r.available("wg") {
		parts = append(parts, "wireguard")
	}
	if r.available("headscale") {
		parts = append(parts, "headscale")
	}
	if len(parts) == 0 {
		return "no backend found — install wireguard-tools, or use --demo"
	}
	return strings.Join(parts, " + ")
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

// Load reads the whole model: WireGuard first, then the control plane. Neither
// missing binary nor a failed read fails the load — each becomes a fact the UI
// can show.
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

	r.loadHeadscale(ctx, &state)
	return state, nil
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

// loadHeadscale reads the control plane, when its binary is present.
func (r *Real) loadHeadscale(ctx context.Context, state *State) {
	run, err := r.runnerFor("headscale")
	if err != nil {
		return
	}
	hs := Headscale{Present: true}

	usersOut, err := run.Read(ctx, "headscale", "users", "list", "--output", "json")
	if err != nil {
		hs.Error = runner.FirstLine(err.Error())
		state.Headscale = hs
		return
	}
	if users, err := ParseUsers([]byte(usersOut)); err == nil {
		hs.Users = users
	}

	if nodesOut, err := run.Read(ctx, "headscale", "nodes", "list", "--output", "json"); err == nil {
		if nodes, err := ParseNodes([]byte(nodesOut)); err == nil {
			hs.Nodes = nodes
		}
	}

	if keysOut, err := run.Read(ctx, "headscale", "preauthkeys", "list", "--output", "json"); err == nil {
		if keys, err := ParsePreAuthKeys([]byte(keysOut)); err == nil {
			hs.PreAuthKeys = keys
		}
	}

	hs.OIDCConfigured = InferOIDC(hs.Users, hs.Nodes)
	state.Headscale = hs
}

// HostFact is a set of unprivileged facts about this host, for --report. None
// of it reads a key, an endpoint or an address: it counts WireGuard interfaces
// and reports whether the control-plane binary is present.
type HostFact struct {
	// WGInterfaces is the number of wireguard-type links, or -1 when the count
	// could not be taken (no ip, or the read failed).
	WGInterfaces int
	// HeadscalePresent reports that the headscale binary was found.
	HeadscalePresent bool
}

// HostFacts probes the host without privilege, for the bug-report block. It
// runs `ip -o link show type wireguard`, an ordinary read, and checks whether
// the headscale binary resolves.
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
	fact.HeadscalePresent = runner.Available("headscale", searchPaths["headscale"]...)
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
