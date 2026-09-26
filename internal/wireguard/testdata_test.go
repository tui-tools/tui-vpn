package wireguard

import (
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// documentationRanges are the address blocks reserved for examples: RFC 5737
// for IPv4 and RFC 3849 for IPv6. Every address in a fixture must be one of
// these, loopback, or the wildcard — nothing that names a real machine.
var documentationRanges = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// TestFixturesCarryNoRealAddress decodes each fixture the way the parsers do
// and fails on any address that is not from a documentation range. It is the
// promise that a fixture pasted from a real machine was scrubbed first.
func TestFixturesCarryNoRealAddress(t *testing.T) {
	files, err := filepath.Glob("testdata/*")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures found: %v", err)
	}

	checked := 0
	for _, path := range files {
		name := filepath.Base(path)
		if name == "README.md" || strings.HasPrefix(name, "fuzz") {
			continue
		}
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(path) //nolint:gosec // testdata is in the repository
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			var addrs []netip.Addr
			switch {
			case strings.HasPrefix(name, "wg-show"):
				for _, dev := range ParseWgDump(string(data)) {
					for _, p := range dev.Peers {
						addrs = append(addrs, endpointAddr(p.Endpoint))
						addrs = append(addrs, prefixAddrs(p.AllowedIPs)...)
					}
				}
			case strings.HasPrefix(name, "ip-route"):
				routes, err := ParseRoutes(data)
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				for _, r := range routes {
					addrs = append(addrs, prefixAddrs([]string{r.Dst, r.Gateway})...)
				}
			case strings.HasPrefix(name, "iptables"):
				addrs = append(addrs, ruleAddrs(ParseIptablesRules(string(data)))...)
			case strings.HasPrefix(name, "firewalld-"):
				// firewall-cmd listings: every address in a rich rule.
				addrs = append(addrs, textAddrs(string(data))...)
			case strings.HasPrefix(name, "nft-"), strings.HasPrefix(name, "tui-firewall-"):
				// JSON rule sets: every token shaped like an address, minus
				// the ones every firewalld and ufw carry (multicast groups
				// and firewalld's built-in 6to4 filter).
				for _, addr := range textAddrs(string(data)) {
					if addr.IsMulticast() || sixToFour.Contains(addr) {
						continue
					}
					addrs = append(addrs, addr)
				}
			default:
				t.Fatalf("no address check for fixture %s: add a case", name)
			}
			for _, addr := range addrs {
				assertDocumentationAddress(t, addr)
			}
			checked++
		})
	}
}

// TestDemoDataCarriesNoRealAddress holds the same promise for the hand-written
// demo state behind --demo.
func TestDemoDataCarriesNoRealAddress(t *testing.T) {
	state := demoState()
	for _, dev := range state.Devices {
		for _, p := range dev.Peers {
			assertDocumentationAddress(t, endpointAddr(p.Endpoint))
			for _, a := range prefixAddrs(p.AllowedIPs) {
				assertDocumentationAddress(t, a)
			}
		}
	}
	for _, r := range state.Routes {
		for _, a := range prefixAddrs([]string{r.Dst, r.Gateway}) {
			assertDocumentationAddress(t, a)
		}
	}
	for _, a := range ruleAddrs(ParseIptablesRules(strings.Join(demoFirewall, "\n"))) {
		assertDocumentationAddress(t, a)
	}
}

// sixToFour is 2002::/16. firewalld's own rule set filters the 6to4
// encodings of the private and reserved IPv4 ranges out of this block, the
// same on every machine.
var sixToFour = netip.MustParsePrefix("2002::/16")

// addrToken is anything shaped like an IPv4 or IPv6 address.
var addrToken = regexp.MustCompile(`[0-9A-Fa-f]*[:.][0-9A-Fa-f:.]+`)

// textAddrs is every token of a text that parses as an address.
func textAddrs(text string) []netip.Addr {
	var addrs []netip.Addr
	for _, tok := range addrToken.FindAllString(text, -1) {
		// A mapped address (::ffff:0.0.0.0) is judged as the IPv4 it maps.
		if a, err := netip.ParseAddr(strings.Trim(tok, ".:")); err == nil {
			addrs = append(addrs, a.Unmap())
		} else if a, err := netip.ParseAddr(tok); err == nil {
			addrs = append(addrs, a.Unmap())
		}
	}
	return addrs
}

// ruleAddrs is every -s and -d address in a ruleset.
func ruleAddrs(fw Firewall) []netip.Addr {
	var addrs []netip.Addr
	for _, rules := range fw.Rules {
		for _, rule := range rules {
			for i := 0; i+1 < len(rule); i++ {
				if rule[i] == "-s" || rule[i] == "-d" {
					addrs = append(addrs, prefixAddrs([]string{rule[i+1]})...)
				}
			}
		}
	}
	return addrs
}

// TestFixturesCarryNoHostName checks the other half of the promise on whatever
// machine the suite runs on.
func TestFixturesCarryNoHostName(t *testing.T) {
	host, err := os.Hostname()
	if err != nil || len(host) < 4 {
		t.Skip("this machine has no host name to look for")
	}
	files, _ := filepath.Glob("testdata/*")
	for _, path := range files {
		data, err := os.ReadFile(path) //nolint:gosec // testdata is in the repository
		if err != nil {
			continue
		}
		if strings.Contains(string(data), host) {
			t.Errorf("%s carries this machine's host name", filepath.Base(path))
		}
	}
}

func assertDocumentationAddress(t *testing.T, addr netip.Addr) {
	t.Helper()
	// Link-local addresses (a cloud's metadata service at 169.254.169.254)
	// are the same on every machine and name none of them.
	if !addr.IsValid() || addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() {
		return
	}
	for _, prefix := range documentationRanges {
		if prefix.Contains(addr) {
			return
		}
	}
	t.Errorf("%s is not a documentation address: replace it with one from "+
		"192.0.2.0/24, 198.51.100.0/24 or 2001:db8::/32 before committing", addr)
}

// endpointAddr extracts the address from an ip:port endpoint.
func endpointAddr(endpoint string) netip.Addr {
	if endpoint == "" {
		return netip.Addr{}
	}
	if ap, err := netip.ParseAddrPort(endpoint); err == nil {
		return ap.Addr()
	}
	return netip.Addr{}
}

// prefixAddrs extracts the address from each CIDR or bare address.
func prefixAddrs(entries []string) []netip.Addr {
	var addrs []netip.Addr
	for _, e := range entries {
		if p, err := netip.ParsePrefix(e); err == nil {
			addrs = append(addrs, p.Addr())
			continue
		}
		if a, err := netip.ParseAddr(e); err == nil {
			addrs = append(addrs, a)
		}
	}
	return addrs
}
