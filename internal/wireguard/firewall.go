package wireguard

import (
	"strings"
)

// This file reads the host firewall's iptables filter table, which is where a
// forwarding server's PostUp rules live, far enough to answer whether the host
// forwards traffic for an interface. Whether a handshake reaches the listen
// port is input.go's question, answered from whichever firewall is really in
// charge (tui-firewall, nftables, iptables).
//
// Both were found wrong on a real cloud VM. The provider's Ubuntu image ships
// an iptables ruleset whose INPUT chain ends in `-j REJECT`, so the listen
// port was closed even with the cloud's own security list open; and its
// FORWARD chain ends in REJECT too, so a rule appended with `-A` lands after
// it and never matches — forwarding rules have to be inserted with `-I`.
//
// The model is `iptables -S` (the filter table, every chain), which needs
// root to read. A read that failed leaves the firewall unchecked.

// Verdict is what the INPUT chain does with a new packet.
type Verdict string

const (
	// VerdictAccept means a rule, or the chain policy, accepts it.
	VerdictAccept Verdict = "accept"
	// VerdictReject means a REJECT rule answers it with an error.
	VerdictReject Verdict = "reject"
	// VerdictDrop means a DROP rule, or the chain policy, discards it.
	VerdictDrop Verdict = "drop"
	// VerdictUnknown means the firewall could not be read, or its rules
	// could not be judged.
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
