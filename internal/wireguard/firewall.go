package wireguard

import (
	"strconv"
	"strings"
)

// This file reads the host firewall far enough to answer two questions about
// a WireGuard interface: does a handshake reach its listen port, and does the
// host forward traffic for it.
//
// Both were found wrong on a real cloud VM. The provider's Ubuntu image ships
// an iptables ruleset whose INPUT chain ends in `-j REJECT`, so the listen
// port was closed even with the cloud's own security list open; and its
// FORWARD chain ends in REJECT too, so a rule appended with `-A` lands after
// it and never matches — forwarding rules have to be inserted with `-I`.
//
// The model is `iptables -S` (the filter table, every chain), which needs
// root to read. A read that failed leaves the firewall unchecked, and every
// answer derived from it "unknown", never "open".

// Verdict is what the INPUT chain does with a new packet.
type Verdict string

const (
	// VerdictAccept means a rule, or the chain policy, accepts it.
	VerdictAccept Verdict = "accept"
	// VerdictReject means a REJECT rule answers it with an error.
	VerdictReject Verdict = "reject"
	// VerdictDrop means a DROP rule, or the chain policy, discards it.
	VerdictDrop Verdict = "drop"
	// VerdictUnknown means the firewall could not be read.
	VerdictUnknown Verdict = "unknown"
)

// Firewall is the filter table as `iptables -S` printed it.
type Firewall struct {
	// Checked reports that the ruleset was read.
	Checked bool
	// Error carries why it could not be (usually: not root).
	Error string
	// Policies is each built-in chain's policy (INPUT → ACCEPT).
	Policies map[string]string
	// Rules is each chain's rules in order, as argument lists without the
	// leading `-A CHAIN`.
	Rules map[string][][]string
}

// ParseIptablesRules reads `iptables -S` into a Firewall. Lines it does not
// understand are ignored: the model only has to be right about -P, -N and -A.
func ParseIptablesRules(out string) Firewall {
	fw := Firewall{Checked: true, Policies: map[string]string{}, Rules: map[string][][]string{}}
	for _, line := range strings.Split(out, "\n") {
		fields := splitRule(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "-P":
			if len(fields) >= 3 {
				fw.Policies[fields[1]] = fields[2]
			}
		case "-N":
			if _, ok := fw.Rules[fields[1]]; !ok {
				fw.Rules[fields[1]] = nil
			}
		case "-A":
			fw.Rules[fields[1]] = append(fw.Rules[fields[1]], fields[2:])
		}
	}
	return fw
}

// splitRule splits one `iptables -S` line into arguments, keeping a double-
// quoted value (a --comment) as one argument.
func splitRule(line string) []string {
	var fields []string
	var b strings.Builder
	quoted, have := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\\' && quoted && i+1 < len(line):
			i++
			b.WriteByte(line[i])
		case c == '"':
			quoted, have = !quoted, true
		case (c == ' ' || c == '\t') && !quoted:
			if have {
				fields = append(fields, b.String())
				b.Reset()
				have = false
			}
		default:
			b.WriteByte(c)
			have = true
		}
	}
	if have {
		fields = append(fields, b.String())
	}
	return fields
}

// UDPPortVerdict walks INPUT the way the kernel would for a new UDP packet to
// port, arriving on some interface other than loopback from some address,
// and says what happens to it. Jumps into user chains (ufw's, docker's) are
// followed. A rule whose match it cannot evaluate — a source address, a
// specific ingress interface, a rate limit — is treated as not matching, so
// an ACCEPT that only some senders get does not count as open.
func (fw Firewall) UDPPortVerdict(port int) Verdict {
	if !fw.Checked {
		return VerdictUnknown
	}
	if v, done := fw.walk("INPUT", port, 0); done {
		return v
	}
	if strings.EqualFold(fw.Policies["INPUT"], "ACCEPT") || fw.Policies["INPUT"] == "" {
		return VerdictAccept
	}
	return VerdictDrop
}

// walk evaluates one chain; done is false when the packet falls off its end
// (or RETURNs) and the caller continues.
func (fw Firewall) walk(chain string, port, depth int) (Verdict, bool) {
	if depth > 16 {
		return VerdictUnknown, false
	}
	for _, rule := range fw.Rules[chain] {
		target, matches := ruleMatchesUDP(rule, port)
		if !matches {
			continue
		}
		switch target {
		case "ACCEPT":
			return VerdictAccept, true
		case "DROP":
			return VerdictDrop, true
		case "REJECT":
			return VerdictReject, true
		case "RETURN":
			return "", false
		case "", "LOG", "NFLOG", "MARK", "CONNMARK", "AUDIT":
			continue
		}
		if _, isChain := fw.Rules[target]; isChain {
			if v, done := fw.walk(target, port, depth+1); done {
				return v, true
			}
		}
	}
	return "", false
}

// ruleMatchesUDP reports the rule's target and whether it matches a new UDP
// packet to port on a non-loopback interface. Unknown conditions do not match.
func ruleMatchesUDP(rule []string, port int) (target string, matches bool) {
	matches = true
	for i := 0; i < len(rule); i++ {
		negated := false
		if rule[i] == "!" && i+1 < len(rule) {
			negated = true
			i++
		}
		arg := rule[i]
		value := ""
		if i+1 < len(rule) {
			value = rule[i+1]
		}
		switch arg {
		case "-j", "-g":
			// Whatever follows the target is the target's own options
			// (--reject-with …), not a match.
			return value, matches
		case "-p":
			i++
			p := strings.ToLower(value)
			hit := p == "udp" || p == "all" || p == "17"
			if hit == negated {
				matches = false
			}
		case "-m":
			i++
			switch value {
			case "udp", "tcp", "comment", "multiport", "state", "conntrack":
			default:
				matches = false // limit, recent, owner, addrtype…
			}
		case "--comment":
			i++
		case "--dport", "--destination-port", "--dports", "--destination-ports":
			i++
			if portListContains(value, port) == negated {
				matches = false
			}
		case "--state", "--ctstate":
			i++
			hit := false
			for _, s := range strings.Split(value, ",") {
				if s == "NEW" {
					hit = true
				}
			}
			if hit == negated {
				matches = false
			}
		case "-i", "--in-interface":
			i++
			// Only "not loopback" is known about the packet: `-i lo` does not
			// match it, `! -i lo` does, and any other interface is unknown.
			if value != "lo" || !negated {
				matches = false
			}
		default:
			// A source or destination address, --sport, and anything else
			// that cannot be judged for "any sender".
			matches = false
			if i+1 < len(rule) && !strings.HasPrefix(rule[i+1], "-") {
				i++
			}
		}
	}
	return target, matches
}

// portListContains reports whether a --dport(s) value (a port, a range a:b,
// or a comma list of either) contains port.
func portListContains(list string, port int) bool {
	for _, part := range strings.Split(list, ",") {
		lo, hi, isRange := strings.Cut(part, ":")
		from, err := strconv.Atoi(lo)
		if err != nil {
			continue
		}
		to := from
		if isRange {
			if to, err = strconv.Atoi(hi); err != nil {
				continue
			}
		}
		if port >= from && port <= to {
			return true
		}
	}
	return false
}

// Forwards reports whether the FORWARD chain accepts traffic coming in on
// iface: the rule a forwarding server's PostUp inserts. It is read from the
// live ruleset, so it says what the host does now, not what a file intends.
func (fw Firewall) Forwards(iface string) bool {
	for _, rule := range fw.Rules["FORWARD"] {
		in, accept := false, false
		for i := 0; i+1 < len(rule); i++ {
			switch {
			case rule[i] == "!" && i+1 < len(rule) && rule[i+1] == "-i":
				i += 2 // a negated interface is not this one
			case rule[i] == "-i" && rule[i+1] == iface:
				in = true
			case rule[i] == "-j" && rule[i+1] == "ACCEPT":
				accept = true
			}
		}
		if in && accept {
			return true
		}
	}
	return false
}

// iptablesSearchPaths are where iptables lives when it is not on PATH:
// /usr/sbin on the distributions that still split sbin.
var iptablesSearchPaths = []string{"/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables"}
