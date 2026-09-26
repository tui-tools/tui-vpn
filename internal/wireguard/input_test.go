package wireguard

import (
	"fmt"
	"strings"
	"testing"
)

// iptablesInput parses an `iptables -S` for the input verdicts, failing the
// test when it does not read.
func iptablesInput(t *testing.T, out string) InputFirewall {
	t.Helper()
	fw, ok := ParseIptablesInput(out)
	if !ok {
		t.Fatal("the iptables ruleset did not read")
	}
	return fw
}

// TestFirewalldFixtures is issue #28: on Fedora 44 with firewalld active,
// captured before and after `firewall-cmd --add-port=51820/udp`. firewalld's
// rules live in its own nftables table, which `iptables -S` never lists, so
// both the nftables read and tui-firewall's model have to see the port open
// only after it was added.
func TestFirewalldFixtures(t *testing.T) {
	cases := []struct {
		fixture string
		parse   func(string) (InputFirewall, bool)
		source  string
		want    Verdict
	}{
		{"nft-firewalld-closed.json", ParseNftRuleset, SourceNftables, VerdictReject},
		{"nft-firewalld-open.json", ParseNftRuleset, SourceNftables, VerdictAccept},
		{"tui-firewall-firewalld-closed.json", ParseTuiFirewallCheck, SourceTUIFirewall, VerdictReject},
		{"tui-firewall-firewalld-open.json", ParseTuiFirewallCheck, SourceTUIFirewall, VerdictAccept},
	}
	for _, tc := range cases {
		fw, ok := tc.parse(readFixture(t, tc.fixture))
		if !ok {
			t.Fatalf("%s did not read", tc.fixture)
		}
		if fw.Source != tc.source || fw.Manager != ManagerFirewalld {
			t.Errorf("%s: source %q manager %q, want %s and firewalld",
				tc.fixture, fw.Source, fw.Manager, tc.source)
		}
		if got := fw.UDPVerdict(51820); got != tc.want {
			t.Errorf("%s: udp/51820 = %s, want %s", tc.fixture, got, tc.want)
		}
		// mdns and dhcpv6-client are allowed in the zone, for a multicast
		// or link-local destination only: nothing a peer sends.
		for _, port := range []int{5353, 546} {
			if got := fw.UDPVerdict(port); got != VerdictReject {
				t.Errorf("%s: udp/%d = %s, want reject for a peer", tc.fixture, port, got)
			}
		}
		// ssh is allowed in the zone: the tcp walk reaches it.
		if got := fw.check(fw.chains[0], "tcp", 22); got != VerdictAccept {
			t.Errorf("%s: tcp/22 = %s, want accept", tc.fixture, got)
		}
	}
}

// TestUFWFixtures: Ubuntu 26.04 with ufw on iptables-nft, only ssh allowed.
// The nftables read follows ufw's jumps from its input hook; tui-firewall's
// model says deny (a drop) by default.
func TestUFWFixtures(t *testing.T) {
	for fixture, parse := range map[string]func(string) (InputFirewall, bool){
		"nft-ufw.json":          ParseNftRuleset,
		"tui-firewall-ufw.json": ParseTuiFirewallCheck,
	} {
		fw, ok := parse(readFixture(t, fixture))
		if !ok {
			t.Fatalf("%s did not read", fixture)
		}
		if fw.Manager != ManagerUFW {
			t.Errorf("%s: manager %q, want ufw", fixture, fw.Manager)
		}
		if got := fw.UDPVerdict(51820); got != VerdictDrop {
			t.Errorf("%s: udp/51820 = %s, want drop", fixture, got)
		}
		if got := fw.check(fw.chains[0], "tcp", 22); got != VerdictAccept {
			t.Errorf("%s: tcp/22 = %s, want accept", fixture, got)
		}
	}
}

// TestUndeterminedIsUnknown: where the reader cannot tell, the column says
// unknown, never closed.
func TestUndeterminedIsUnknown(t *testing.T) {
	// A jump to a chain that is not in what was read may end anywhere.
	fw := iptablesInput(t, "-P INPUT DROP\n-A INPUT -j somewhere\n")
	if got := fw.UDPVerdict(51820); got != VerdictUnknown {
		t.Errorf("unfollowable jump: %s, want unknown", got)
	}
	// Chains nested past the kernel's limit.
	var b strings.Builder
	b.WriteString("-P INPUT DROP\n")
	for i := range maxJumpDepth + 2 {
		fmt.Fprintf(&b, "-N c%d\n", i)
	}
	b.WriteString("-A INPUT -j c0\n")
	for i := range maxJumpDepth + 1 {
		fmt.Fprintf(&b, "-A c%d -j c%d\n", i, i+1)
	}
	if got := iptablesInput(t, b.String()).UDPVerdict(51820); got != VerdictUnknown {
		t.Errorf("too deep: %s, want unknown", got)
	}
	// A firewalld zone that allows a service this reader cannot turn into
	// ports: the port may be in it.
	zone := func(extra string) string {
		return `{"enabled":true,"model":{"Backend":"firewalld","Groups":[{"Name":"public",` +
			`"Title":"public (default)","Description":"active  ·  interfaces: eth0",` +
			`"Default":{"Target":"default"},"Rules":[` +
			`{"Kind":"service","Action":"ALLOW","Service":"ssh","Extra":{"scope":"both"}},` +
			`{"Kind":"service","Action":"ALLOW","Service":"some-vpn","Extra":{"scope":"both"}}` +
			extra + `]}]}}`
	}
	fw, _ = ParseTuiFirewallCheck(zone(""))
	if got := fw.UDPVerdict(51820); got != VerdictUnknown {
		t.Errorf("unknown firewalld service: %s, want unknown", got)
	}
	// The same zone with the port itself allowed is open, whatever the
	// unknown service is.
	fw, _ = ParseTuiFirewallCheck(zone(`,{"Kind":"port","Action":"ALLOW","Proto":"udp",` +
		`"Ports":"51820","Extra":{"scope":"runtime"}}`))
	if got := fw.UDPVerdict(51820); got != VerdictAccept {
		t.Errorf("allowed port next to an unknown service: %s, want accept", got)
	}
	// A port only in the permanent configuration is not open yet.
	fw, _ = ParseTuiFirewallCheck(strings.Replace(zone(`,{"Kind":"port","Action":"ALLOW",`+
		`"Proto":"udp","Ports":"51820","Extra":{"scope":"permanent"}}`), "some-vpn", "wireguard", 1))
	if got := fw.UDPVerdict(51821); got != VerdictReject {
		t.Errorf("udp/51821 with only the wireguard service: %s, want reject", got)
	}
	if got := fw.UDPVerdict(51820); got != VerdictAccept {
		t.Errorf("the wireguard service is 51820/udp: %s, want accept", got)
	}
	// Nothing read at all.
	if got := (InputFirewall{Error: "you must be root"}).UDPVerdict(51820); got != VerdictUnknown {
		t.Errorf("unread: %s, want unknown", got)
	}
}

// TestFirewalldZonesThatApply: only the default zone and the zones an
// interface is bound to meet a peer's packet; a zone bound by source only,
// an inactive zone and a policy object are left out, and a firewall that is
// off refuses nothing.
func TestFirewalldZonesThatApply(t *testing.T) {
	check := `{"enabled":true,"model":{"Backend":"firewalld","Groups":[
		{"Name":"public","Title":"public (default)","Description":"active",
		 "Default":{"Target":"default"},"Rules":[
		 {"Kind":"port","Action":"ALLOW","Proto":"udp","Ports":"51820","Extra":{"scope":"both"}}]},
		{"Name":"drop","Title":"drop","Description":"",
		 "Default":{"Target":"DROP"},"Rules":[]},
		{"Name":"internal","Title":"internal","Description":"active  ·  sources: 192.0.2.0/24",
		 "Default":{"Target":"DROP"},"Rules":[]},
		{"Name":"policy/allow-host-ipv6","Title":"allow-host-ipv6","Description":"active  ·  interfaces: x",
		 "Default":{"Target":"REJECT"},"Rules":[]}]}}`
	fw, ok := ParseTuiFirewallCheck(check)
	if !ok || len(fw.chains) != 1 {
		t.Fatalf("zones kept: %d, want the default zone only", len(fw.chains))
	}
	if got := fw.UDPVerdict(51820); got != VerdictAccept {
		t.Errorf("udp/51820 = %s, want accept", got)
	}
	bound := strings.Replace(check, `"Description":""`, `"Description":"active  ·  interfaces: eth1"`, 1)
	fw, _ = ParseTuiFirewallCheck(bound)
	if got := fw.UDPVerdict(51820); got != VerdictDrop {
		t.Errorf("with a DROP zone bound to an interface: %s, want drop", got)
	}
	off, _ := ParseTuiFirewallCheck(`{"enabled":false,"model":{"Backend":"firewalld"}}`)
	if got := off.UDPVerdict(51820); got != VerdictAccept {
		t.Errorf("firewalld off: %s, want accept", got)
	}
}

// TestNftWithoutInputHook: an nftables rule set with no input base chain
// filters nothing, and says so, so the real read can ask iptables-legacy.
func TestNftWithoutInputHook(t *testing.T) {
	fw, ok := ParseNftRuleset(`{"nftables":[{"metainfo":{"json_schema_version":1}}]}`)
	if !ok || !fw.unhooked || fw.UDPVerdict(51820) != VerdictAccept {
		t.Errorf("empty rule set: ok %v unhooked %v verdict %s", ok, fw.unhooked, fw.UDPVerdict(51820))
	}
	if _, ok := ParseNftRuleset("nft: Operation not permitted"); ok {
		t.Error("an error message read as a rule set")
	}
}

// TestBuildOpenListenPortFor: firewalld gets firewall-cmd, anything else the
// iptables rule.
func TestBuildOpenListenPortFor(t *testing.T) {
	cmd, err := BuildOpenListenPortFor(ManagerFirewalld, 51820)
	if err != nil || strings.Join(cmd.Argv, " ") != "firewall-cmd --add-port=51820/udp" {
		t.Errorf("firewalld: %q, %v", cmd.Argv, err)
	}
	for _, manager := range []string{"", ManagerUFW} {
		cmd, err := BuildOpenListenPortFor(manager, 51820)
		if err != nil || cmd.Argv[0] != "iptables" {
			t.Errorf("%q: %q, %v", manager, cmd.Argv, err)
		}
	}
	if _, err := BuildOpenListenPortFor(ManagerFirewalld, 0); err == nil {
		t.Error("port 0 was accepted")
	}
}
