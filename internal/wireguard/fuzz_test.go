package wireguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The family rule is that every package turning bytes it did not write into
// values the tool acts on carries a Go native fuzz test, seeded from the
// package's testdata — see
// https://github.com/tui-tools/tui-kit/blob/main/templates/FUZZING.md.
//
// This package has three parsers (the wg dump, `iptables -S` and `ip -j
// route`) and one command builder that takes a public key and a set of
// allowed-ips from outside. Each has a target below. The invariant, not the output, is what is
// asserted: for any input at all, a parser never panics and never returns a
// value that breaks the model, and the builder never produces a runnable
// command that carries something it should not.
//
// Run one for real with, e.g.:
//
//	go test -run=^$ -fuzz=FuzzParseWgDump -fuzztime=2m ./internal/wireguard/

// seedFrom adds every fixture whose name starts with prefix to the corpus,
// alongside the shapes a real capture never has.
func seedFrom(f *testing.F, prefix string) {
	f.Helper()
	files, err := filepath.Glob("testdata/" + prefix + "*")
	if err != nil {
		f.Fatalf("glob: %v", err)
	}
	for _, path := range files {
		data, err := os.ReadFile(path) //nolint:gosec // testdata is in the repository
		if err != nil {
			f.Fatalf("read %s: %v", path, err)
		}
		f.Add(string(data))
	}
	for _, seed := range []string{
		"", "\n", "\t", " ", "\t\t\t\t", ":", "::",
		"[]", "{}", "null", "[{}]", `[{"id":1}]`, `{"users":null}`,
		"wg0\t(none)\t(none)\t0\toff\n",
		"wg0\ta\tb\tc\td\te\tf\tg\th\n",
		strings.Repeat("\t", 9) + "\n",
		strings.Repeat("A", 4096),
	} {
		f.Add(seed)
	}
}

func FuzzParseWgDump(f *testing.F) {
	seedFrom(f, "wg-show")
	f.Fuzz(func(t *testing.T, dump string) {
		for _, dev := range ParseWgDump(dump) {
			// A device the parser returns must be usable: a name, and peers
			// whose counters are never negative and whose allowed-ips are all
			// non-empty.
			if dev.Name == "" {
				t.Fatalf("device with an empty name from %q", dump)
			}
			if dev.ListenPort < 0 {
				t.Fatalf("negative listen port: %d", dev.ListenPort)
			}
			for _, p := range dev.Peers {
				if p.RxBytes < 0 || p.TxBytes < 0 {
					t.Fatalf("negative counter on a peer: %+v", p)
				}
				for _, ip := range p.AllowedIPs {
					if ip == "" {
						t.Fatalf("empty allowed-ip kept: %+v", p)
					}
				}
			}
		}
	})
}

// FuzzParseIptablesRules feeds arbitrary rulesets to the firewall parser. The
// verdict it derives for a port decides whether the new-interface wizard
// offers to open that port, so for any input it has to be one of the four
// verdicts, and walking the chains (jumps included) has to terminate.
func FuzzParseIptablesRules(f *testing.F) {
	seedFrom(f, "iptables")
	f.Add("-N a\n-A INPUT -j a\n-A a -j INPUT\n")
	f.Fuzz(func(t *testing.T, out string) {
		fw := ParseIptablesRules(out)
		switch v := fw.UDPPortVerdict(51820); v {
		case VerdictAccept, VerdictReject, VerdictDrop, VerdictUnknown:
		default:
			t.Fatalf("verdict %q is not one of the four", v)
		}
		_ = fw.Forwards("wg0")
	})
}

// FuzzParseRoutes feeds arbitrary JSON to the route parser, whose answer
// proposes a forwarding server's networks and egress: whatever parses, the
// proposals built from it must never be empty strings.
func FuzzParseRoutes(f *testing.F) {
	seedFrom(f, "ip-route")
	f.Fuzz(func(t *testing.T, data string) {
		routes, err := ParseRoutes([]byte(data))
		if err != nil {
			return
		}
		for _, n := range ForwardCandidates(routes, map[string]bool{"lo": true}) {
			if n == "" {
				t.Fatalf("empty network proposed from %q", data)
			}
		}
		_ = DefaultRouteDevice(routes)
	})
}

// FuzzBuildAddPeer feeds arbitrary keys and allowed-ips through the one builder
// that takes both from outside. Whatever comes back is what the confirm dialog
// will show and the runner will execute, so the shape has to hold for every
// input: a failure returns nothing runnable, and a success carries the key as a
// single argument and never a private-key token.
func FuzzBuildAddPeer(f *testing.F) {
	f.Add("wg0", testPub, "192.0.2.5/32")
	f.Add("wg0", "not-a-key", "x")
	f.Add("", "", "")
	f.Add("wg0", testPub, "192.0.2.5/32,2001:db8::5/128")
	f.Add("wg0", testPub, "--flag")
	f.Add("wg0", testPub, "a b\tc")

	f.Fuzz(func(t *testing.T, iface, key, ips string) {
		cmd, err := BuildAddPeer(iface, key, strings.Split(ips, ","), "")
		if err != nil {
			if len(cmd.Argv) != 0 {
				t.Fatalf("failed with a non-empty command: %+v", cmd)
			}
			return
		}
		if len(cmd.Argv) < 7 {
			t.Fatalf("a successful add-peer has at least seven arguments: %q", cmd.Argv)
		}
		if cmd.Argv[4] != key {
			t.Fatalf("the public key was not carried as a single argument: %q", cmd.Argv)
		}
		for _, tok := range cmd.Argv {
			if strings.Contains(tok, "private-key") {
				t.Fatalf("built a command with a private-key token: %q", cmd.Argv)
			}
		}
	})
}
