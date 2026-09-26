package wireguard

import (
	"encoding/json"
	"strconv"
	"strings"
)

// This file answers one question for the UDP IN column and --check's
// listenPortInput: does a handshake from anywhere reach a listen port, or
// does the host firewall refuse it?
//
// `iptables -S` alone was not enough (issue #28). On Fedora, firewalld keeps
// its rules in its own nftables table, which iptables never lists, so a port
// firewalld accepts read as closed. The read now prefers tui-firewall's own
// --check, which already understands ufw, firewalld, nftables and iptables;
// without it, the rule set is read from `nft -j list ruleset`, and only then
// from `iptables -S`. Every source is reduced to the same few facts per rule,
// and a rule this reader cannot judge (a match on something it does not
// model) never decides the answer by itself.
//
// A jump or a goto is followed into the chain it names: ufw is an input chain
// whose rules are nothing but jumps, and firewalld's accept for a port sits
// three chains down from its input hook. When a jump cannot be followed (its
// chain is not in what was read, or the chains nest deeper than the kernel
// allows), or a rule names a service whose ports are not known here, the
// answer is unknown rather than closed: what comes after it cannot be trusted.
//
// The reader is the one tui-tailscale uses for its readiness ports step
// (internal/headscale/ports.go there), copied rather than imported, adapted
// to keep a reject apart from a drop and to read firewalld's zones out of
// tui-firewall's model.

// Firewall managers the input read recognises.
const (
	ManagerFirewalld = "firewalld"
	ManagerUFW       = "ufw"
)

// Input firewall sources, in the order they are tried.
const (
	SourceTUIFirewall = "tui-firewall"
	SourceNftables    = "nftables"
	SourceIptables    = "iptables"
)

// inRule is one input rule, reduced to what decides a port: its verdict, the
// protocol and ports it matches, and whether it matches anything else.
type inRule struct {
	// verdict is accept, reject, drop, unknown (a rule that may accept or
	// refuse, and nobody here can tell), jump or goto (to target), return, or
	// skip for anything that does not end the walk (a log, a counter, a
	// mark).
	verdict string
	// target is the chain a jump or a goto continues in.
	target string
	// addrtype marks iptables-nft's address-type match, whose type the JSON
	// does not carry. On the input path it is ufw's "not local" guard, whose
	// first rule returns for a packet addressed to this host: a return under
	// it is taken, anything else under it says nothing about peers.
	addrtype bool
	// proto is tcp, udp, or empty for any.
	proto string
	// ports are the destination port ranges, none for any.
	ports [][2]int
	// narrow reports a match on something beyond protocol and port: an
	// interface, a source, established connections only, an ICMP type. Such
	// a rule says nothing about new packets from peers.
	narrow bool
	// xtState marks iptables-nft's state match, whose states the JSON does
	// not carry.
	xtState bool
}

// inChain is one chain: its rules in order and, for an input base chain, its
// policy.
type inChain struct {
	rules []inRule
	// policy is accept, reject, drop, or empty when unknown.
	policy string
	// table names the table the chain belongs to, which is where its jumps
	// are looked up.
	table string
}

// maxJumpDepth is how deep chains may nest: the kernel's own limit for
// nftables, well past anything ufw or firewalld builds.
const maxJumpDepth = 16

// InputFirewall is what the input read found: where from, and the IPv4 input
// chains.
type InputFirewall struct {
	// Source is tui-firewall, nftables or iptables; empty when nothing
	// could be read.
	Source string
	// Error is why nothing could be read.
	Error string
	// Manager is the firewall manager in charge when one was recognised:
	// firewalld or ufw, empty otherwise. It decides how a port is opened:
	// firewalld rejects in its own table whatever it does not allow, so a
	// rule inserted into iptables' INPUT chain would never be reached.
	Manager string
	// chains are the input base chains, where a packet starts; named are
	// every other chain a jump can reach, by table and name.
	chains []inChain
	named  map[string]inChain
	// unhooked reports an nftables rule set with no input base chain at
	// all. It means nothing filters input, unless the host filters with
	// iptables-legacy, whose rules nft never lists: then iptables is asked.
	unhooked bool
}

// chainKey keys a regular chain by its table and name.
func chainKey(table, name string) string { return table + "\x00" + name }

// UDPVerdict judges a listen port: refused when any input chain would refuse
// a new UDP packet to it (reject or drop, as that chain does), accepted when
// every chain accepts it, unknown otherwise, and unknown when nothing was
// read.
func (f InputFirewall) UDPVerdict(port int) Verdict {
	if f.Source == "" || len(f.chains) == 0 {
		return VerdictUnknown
	}
	verdict := VerdictAccept
	for _, chain := range f.chains {
		switch v := f.check(chain, "udp", port); v {
		case VerdictReject, VerdictDrop:
			return v
		case VerdictUnknown:
			verdict = VerdictUnknown
		}
	}
	return verdict
}

// check walks one base chain the way the kernel would for a new packet from
// anywhere, and falls back on its policy when no rule decided.
func (f InputFirewall) check(c inChain, proto string, port int) Verdict {
	if v, decided := f.walk(c, proto, port, 0); decided {
		return v
	}
	switch c.policy {
	case "accept":
		return VerdictAccept
	case "reject":
		return VerdictReject
	case "drop":
		return VerdictDrop
	}
	return VerdictUnknown
}

// walk goes through one chain's rules, into the chains they jump to, and
// reports the verdict when one was reached; not decided means the packet
// fell off the end of the chain (or returned) to whoever called it.
func (f InputFirewall) walk(c inChain, proto string, port, depth int) (Verdict, bool) {
	for _, r := range c.rules {
		if !r.applies(proto, port) {
			continue
		}
		switch r.verdict {
		case "accept":
			return VerdictAccept, true
		case "reject":
			return VerdictReject, true
		case "drop":
			return VerdictDrop, true
		case "unknown":
			return VerdictUnknown, true
		case "return":
			return "", false
		case "jump", "goto":
			target, ok := f.named[chainKey(c.table, r.target)]
			if !ok || depth >= maxJumpDepth {
				// A jump that cannot be followed may end anywhere.
				return VerdictUnknown, true
			}
			if v, decided := f.walk(target, proto, port, depth+1); decided {
				return v, true
			}
			if r.verdict == "goto" {
				// A goto does not come back: its chain's end is this one's.
				return "", false
			}
		}
	}
	return "", false
}

// applies reports whether a rule takes a new packet from anywhere to this
// host on the port: it ends somewhere, and matches nothing narrower than the
// protocol and the port.
func (r inRule) applies(proto string, port int) bool {
	if r.verdict == "skip" || r.narrow {
		return false
	}
	if r.addrtype && r.verdict != "return" {
		return false
	}
	if r.proto != "" && r.proto != proto {
		return false
	}
	return len(r.ports) == 0 || inRanges(r.ports, port)
}

// inRanges reports whether a port is in one of the ranges.
func inRanges(ranges [][2]int, port int) bool {
	for _, r := range ranges {
		if port >= r[0] && port <= r[1] {
			return true
		}
	}
	return false
}

// parsePorts reads "80,443", "1000:2000" or "1000-2000" lists.
func parsePorts(s string) [][2]int {
	var out [][2]int
	for _, item := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		lo, hi, isRange := strings.Cut(item, ":")
		if !isRange {
			lo, hi, isRange = strings.Cut(item, "-")
		}
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			continue
		}
		b := a
		if isRange {
			if v, err := strconv.Atoi(strings.TrimSpace(hi)); err == nil {
				b = v
			}
		}
		out = append(out, [2]int{a, b})
	}
	return out
}

// policyWord folds the words firewalls use for a default, and firewalld's
// zone targets, into accept, reject or drop.
func policyWord(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "accept", "allow":
		return "accept"
	case "reject", "%%reject%%", "default":
		// firewalld's "default" target rejects what the zone does not allow.
		return "reject"
	case "drop", "deny", "limit-deny":
		return "drop"
	}
	return ""
}

// --- tui-firewall --check ---------------------------------------------------

// tuiFirewallRule is one rule of tui-firewall's model, as --check prints it.
type tuiFirewallRule struct {
	Kind      string            `json:"Kind"`
	Action    string            `json:"Action"`
	Direction string            `json:"Direction"`
	Proto     string            `json:"Proto"`
	Ports     string            `json:"Ports"`
	From      string            `json:"From"`
	Service   string            `json:"Service"`
	Raw       string            `json:"Raw"`
	Extra     map[string]string `json:"Extra"`
}

// tuiFirewallGroup is one group of tui-firewall's model: ufw's single rule
// list, an nftables chain, or a firewalld zone.
type tuiFirewallGroup struct {
	Name        string `json:"Name"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Default     struct {
		Incoming string `json:"Incoming"`
		Target   string `json:"Target"`
	} `json:"Default"`
	Rules []tuiFirewallRule `json:"Rules"`
}

// ParseTuiFirewallCheck reads tui-firewall's --check JSON: whether the
// firewall is on, and each input group's default and rules, the way its model
// prints them for ufw, nftables, iptables and firewalld.
func ParseTuiFirewallCheck(out string) (InputFirewall, bool) {
	start := strings.IndexByte(out, '{')
	if start < 0 {
		return InputFirewall{}, false
	}
	var report struct {
		Enabled bool `json:"enabled"`
		Model   struct {
			Backend string             `json:"Backend"`
			Groups  []tuiFirewallGroup `json:"Groups"`
		} `json:"model"`
	}
	if err := json.NewDecoder(strings.NewReader(out[start:])).Decode(&report); err != nil {
		return InputFirewall{}, false
	}
	fw := InputFirewall{Source: SourceTUIFirewall}
	switch backend := strings.ToLower(report.Model.Backend); backend {
	case ManagerFirewalld, ManagerUFW:
		fw.Manager = backend
	}
	if !report.Enabled {
		// A firewall that is off refuses nothing.
		fw.chains = []inChain{{policy: "accept"}}
		return fw, true
	}
	if strings.EqualFold(report.Model.Backend, "firewalld") {
		fw.chains = firewalldZones(report.Model.Groups)
		return fw, true
	}
	for _, g := range report.Model.Groups {
		name := strings.ToLower(g.Name)
		if g.Default.Incoming == "" || strings.HasPrefix(name, "ip6 ") {
			continue
		}
		chain := inChain{policy: policyWord(g.Default.Incoming)}
		for _, r := range g.Rules {
			if dir := strings.ToUpper(r.Direction); dir != "" && dir != "IN" {
				continue
			}
			chain.rules = append(chain.rules, tuiFirewallRuleOf(r))
		}
		fw.chains = append(fw.chains, chain)
	}
	return fw, true
}

// tuiFirewallRuleOf reduces one ufw, nftables or iptables rule of the model.
func tuiFirewallRuleOf(r tuiFirewallRule) inRule {
	rule := inRule{proto: strings.ToLower(r.Proto), ports: parsePorts(r.Ports)}
	unknownService := false
	if len(rule.ports) == 0 && r.Service != "" {
		var proto string
		proto, rule.ports, unknownService = servicePorts(r.Service)
		if proto != "" {
			rule.proto = proto
		}
	}
	raw := strings.ToLower(r.Raw)
	switch strings.ToUpper(r.Action) {
	case "ALLOW", "ACCEPT", "LIMIT":
		rule.verdict = "accept"
	case "REJECT":
		rule.verdict = "reject"
	case "DENY", "DROP":
		rule.verdict = "drop"
	case "":
		// nftables' model leaves an xt REJECT target without an action; its
		// raw text still names it.
		switch {
		case strings.Contains(raw, "reject"):
			rule.verdict = "reject"
		case strings.Contains(raw, " drop"):
			rule.verdict = "drop"
		default:
			rule.verdict = "skip"
		}
	default:
		rule.verdict = "skip"
	}
	from := strings.ToLower(strings.TrimSpace(r.From))
	if from != "" && from != "anywhere" && from != "any" && from != "0.0.0.0/0" {
		rule.narrow = true
	}
	if strings.Contains(raw, "iifname") || strings.Contains(raw, "saddr") ||
		(rule.proto == "" && len(rule.ports) == 0 &&
			(strings.Contains(raw, "conntrack") || strings.Contains(raw, "ct state") ||
				strings.Contains(raw, "icmp"))) {
		rule.narrow = true
	}
	if rule.proto == "icmp" || rule.proto == "ipv6-icmp" {
		rule.narrow = true
	}
	if localOnlyServices[strings.ToLower(r.Service)] {
		rule.narrow = true
	}
	if unknownService && !rule.narrow && rule.verdict != "skip" {
		// A service this reader does not know stands for ports it cannot
		// name: if the walk gets that far, the answer is unknown.
		rule.verdict, rule.proto, rule.ports = "unknown", "", nil
	}
	return rule
}

// firewalldZones turns firewalld's zones, as tui-firewall models them, into
// the chains a packet from a peer can meet: the default zone, which takes
// every interface no other zone claims, and every active zone an interface
// is bound to. A zone bound by source address only is for some senders, not
// for everyone, and a policy object is left out.
//
// Inside a zone the order of entries does not matter to firewalld: a rich
// rule that refuses comes first, then any entry that accepts, then an entry
// this reader cannot turn into ports (unknown), then the zone target.
func firewalldZones(groups []tuiFirewallGroup) []inChain {
	var chains []inChain
	for _, g := range groups {
		if strings.HasPrefix(g.Name, "policy/") {
			continue
		}
		isDefault := strings.HasSuffix(g.Title, "(default)")
		bound := strings.Contains(g.Description, "active") &&
			strings.Contains(g.Description, "interfaces:")
		if !isDefault && !bound {
			continue
		}
		var refuse, accept, unknown []inRule
		for _, r := range g.Rules {
			if r.Extra["scope"] == "permanent" {
				// Not in the running configuration until a reload.
				continue
			}
			rule, ok := firewalldRule(r)
			if !ok {
				continue
			}
			switch rule.verdict {
			case "accept":
				accept = append(accept, rule)
			case "unknown":
				unknown = append(unknown, rule)
			default:
				refuse = append(refuse, rule)
			}
		}
		rules := append(append(refuse, accept...), unknown...)
		chains = append(chains, inChain{rules: rules, policy: policyWord(g.Default.Target)})
	}
	return chains
}

// firewalldRule reduces one zone entry: a service, a port, a protocol or a
// rich rule. Interface and source bindings, masquerade, forwarding and ICMP
// blocks say nothing about a UDP port, and are not rules here.
func firewalldRule(r tuiFirewallRule) (inRule, bool) {
	switch r.Kind {
	case "service":
		proto, ports, unknown := servicePorts(r.Service)
		if unknown {
			return inRule{verdict: "unknown"}, true
		}
		return inRule{verdict: "accept", proto: proto, ports: ports,
			narrow: localOnlyServices[strings.ToLower(r.Service)]}, true
	case "port":
		return inRule{verdict: "accept", proto: strings.ToLower(r.Proto),
			ports: parsePorts(r.Ports)}, true
	case "protocol":
		proto := strings.ToLower(strings.TrimSpace(r.Raw))
		if proto != "udp" && proto != "tcp" {
			return inRule{}, false
		}
		return inRule{verdict: "accept", proto: proto}, true
	case "rich":
		rule := tuiFirewallRuleOf(r)
		if rule.verdict == "skip" {
			return inRule{}, false
		}
		if r.Service == "" && r.Ports == "" && !rule.narrow {
			// A rich rule on something this reader does not decompose (a
			// destination, a mark): it cannot decide for everyone.
			rule.narrow = true
		}
		return rule, !rule.narrow
	}
	return inRule{}, false
}

// localOnlyServices are the firewalld services whose rules match only a
// multicast or link-local destination (mdns: 224.0.0.251, dhcpv6-client:
// fe80::/64), never a packet a peer sends to this host's own address.
var localOnlyServices = map[string]bool{"mdns": true, "dhcpv6-client": true}

// servicePorts is the protocol and ports of the services a WireGuard host
// usually has open, when a rule names the service rather than its port: ufw
// application profiles and firewalld's own service definitions. The third
// value reports a service this reader does not know.
func servicePorts(service string) (string, [][2]int, bool) {
	switch strings.ToLower(service) {
	case "wireguard":
		return "udp", [][2]int{{51820, 51820}}, false
	case "ssh", "openssh":
		return "tcp", [][2]int{{22, 22}}, false
	case "https", "nginx https", "apache secure":
		return "tcp", [][2]int{{443, 443}}, false
	case "http", "nginx http", "www":
		return "tcp", [][2]int{{80, 80}}, false
	case "nginx full", "apache full", "www full":
		return "tcp", [][2]int{{80, 80}, {443, 443}}, false
	case "cockpit":
		return "tcp", [][2]int{{9090, 9090}}, false
	case "dhcpv6-client":
		return "udp", [][2]int{{546, 546}}, false
	case "dhcp":
		return "udp", [][2]int{{67, 67}}, false
	case "mdns":
		return "udp", [][2]int{{5353, 5353}}, false
	case "dns":
		// Both protocols: a rule on no protocol.
		return "", [][2]int{{53, 53}}, false
	}
	return "", nil, true
}

// --- iptables -S ---------------------------------------------------------------

// iptablesTable is the one table `iptables -S` lists: filter.
const iptablesTable = "filter"

// ParseIptablesInput reads `iptables -S`: the INPUT chain, and every chain
// its jumps reach. Output limited to `iptables -S INPUT` still reads; a jump
// there names a chain that is not in it, which makes the answer unknown.
func ParseIptablesInput(out string) (InputFirewall, bool) {
	var lines [][]string
	for _, line := range strings.Split(out, "\n") {
		lines = append(lines, splitRule(strings.TrimSpace(line)))
	}
	// Chains are declared with -N, before or after the rules that jump to
	// them; the built-in ones are always there.
	chains := map[string]*inChain{}
	for _, name := range []string{"INPUT", "FORWARD", "OUTPUT"} {
		chains[name] = &inChain{table: iptablesTable}
	}
	for _, f := range lines {
		if len(f) >= 2 && f[0] == "-N" {
			chains[f[1]] = &inChain{table: iptablesTable}
		}
	}
	seen := false
	for _, f := range lines {
		if len(f) < 2 {
			continue
		}
		c, ok := chains[f[1]]
		if !ok {
			continue
		}
		switch f[0] {
		case "-P":
			seen = seen || f[1] == "INPUT"
			if len(f) >= 3 {
				c.policy = policyWord(f[2])
			}
		case "-A":
			seen = seen || f[1] == "INPUT"
			c.rules = append(c.rules, iptablesRule(f[2:]))
		}
	}
	if !seen {
		return InputFirewall{}, false
	}
	fw := InputFirewall{Source: SourceIptables, chains: []inChain{*chains["INPUT"]},
		named: map[string]inChain{}}
	for name, c := range chains {
		if strings.HasPrefix(name, "ufw-") {
			fw.Manager = ManagerUFW
		}
		if name != "INPUT" {
			fw.named[chainKey(iptablesTable, name)] = *c
		}
	}
	return fw, true
}

// nonTerminal are the iptables targets that let the packet go on to the next
// rule: a log, a mark, a counter of some kind.
var nonTerminal = map[string]bool{
	"LOG": true, "NFLOG": true, "ULOG": true, "MARK": true, "CONNMARK": true,
	"TRACE": true, "AUDIT": true, "CT": true, "NOTRACK": true, "TCPMSS": true,
	"SET": true, "CLASSIFY": true, "DSCP": true, "TOS": true, "TTL": true,
	"HL": true, "SECMARK": true, "CONNSECMARK": true, "IDLETIMER": true, "LED": true,
}

// iptablesModules are the -m matches whose options this reader judges; any
// other module (limit, recent, owner, set…) narrows the rule to some packets.
var iptablesModules = map[string]bool{
	"udp": true, "tcp": true, "multiport": true, "comment": true,
	"state": true, "conntrack": true, "addrtype": true,
}

// iptablesRule reduces one `-A <chain> …` rule. Everything after the target
// is the target's own options (--reject-with …), not a match.
func iptablesRule(args []string) inRule {
	r := inRule{verdict: "skip"}
	for i := 0; i < len(args); i++ {
		next := ""
		if i+1 < len(args) {
			next = args[i+1]
		}
		switch args[i] {
		case "-p", "--protocol":
			r.proto = strings.ToLower(next)
			switch r.proto {
			case "all", "0":
				r.proto = ""
			case "17":
				r.proto = "udp"
			case "6":
				r.proto = "tcp"
			case "tcp", "udp":
			default:
				r.narrow = true // icmp, sctp…
			}
			i++
		case "-m", "--match":
			if !iptablesModules[next] {
				r.narrow = true
			}
			i++
		case "--dport", "--dports", "--destination-port", "--destination-ports":
			r.ports = parsePorts(next)
			i++
		case "--comment":
			i++
		case "-s", "--source", "-d", "--destination":
			if next != "0.0.0.0/0" {
				r.narrow = true
			}
			i++
		case "--dst-type":
			// A packet a peer sends to this host is addressed to one of its
			// own addresses: LOCAL matches it, any other type does not.
			if !strings.EqualFold(next, "LOCAL") {
				r.narrow = true
			}
			i++
		case "--state", "--ctstate":
			if !strings.Contains(strings.ToUpper(next), "NEW") {
				r.narrow = true
			}
			i++
		case "-j", "--jump":
			switch target := strings.ToUpper(next); {
			case target == "ACCEPT":
				r.verdict = "accept"
			case target == "DROP":
				r.verdict = "drop"
			case target == "REJECT":
				r.verdict = "reject"
			case target == "RETURN":
				r.verdict = "return"
			case nonTerminal[target]:
			default:
				r.verdict, r.target = "jump", next
			}
			return r
		case "-g", "--goto":
			r.verdict, r.target = "goto", next
			return r
		case "!":
			// Only "not loopback" is known about the packet: `! -i lo` takes
			// it, and any other negated match is beyond this reader.
			if next == "-i" && i+2 < len(args) && args[i+2] == "lo" {
				i += 2
				continue
			}
			r.narrow = true
		default:
			// An interface, a source port, and any match this reader does not
			// model: not a rule about every peer.
			r.narrow = true
			if next != "" && !strings.HasPrefix(next, "-") && next != "!" {
				i++
			}
		}
	}
	return r
}

// --- nft -j list ruleset --------------------------------------------------------

// ParseNftRuleset reads `nft -j list ruleset`: every IPv4-capable base chain
// hooked to input, its policy and its rules, and every other chain of those
// families, for the jumps to follow.
func ParseNftRuleset(out string) (InputFirewall, bool) {
	start := strings.IndexByte(out, '{')
	if start < 0 {
		return InputFirewall{}, false
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out[start:]), &doc); err != nil {
		return InputFirewall{}, false
	}
	type key struct{ family, table, name string }
	chains := map[key]*inChain{}
	var order []key
	manager := ""
	for _, obj := range doc.Nftables {
		raw, ok := obj["table"]
		if !ok {
			continue
		}
		var t struct{ Family, Name string }
		if json.Unmarshal(raw, &t) == nil && t.Family == "inet" && t.Name == "firewalld" {
			manager = ManagerFirewalld
		}
	}
	for _, obj := range doc.Nftables {
		raw, ok := obj["chain"]
		if !ok {
			continue
		}
		var c struct {
			Family, Table, Name, Hook, Type, Policy string
		}
		if json.Unmarshal(raw, &c) != nil || (c.Family != "ip" && c.Family != "inet") {
			continue
		}
		k := key{c.Family, c.Table, c.Name}
		if manager == "" && strings.HasPrefix(c.Name, "ufw-") {
			manager = ManagerUFW
		}
		switch {
		case c.Hook == "input" && (c.Type == "" || c.Type == "filter"):
			chains[k] = &inChain{policy: policyWord(c.Policy), table: c.Family + " " + c.Table}
			order = append(order, k)
		case c.Hook == "":
			// A regular chain: reached only by a jump or a goto.
			chains[k] = &inChain{table: c.Family + " " + c.Table}
		}
	}
	for _, obj := range doc.Nftables {
		raw, ok := obj["rule"]
		if !ok {
			continue
		}
		var r struct {
			Family, Table, Chain string
			Expr                 []map[string]json.RawMessage
		}
		if json.Unmarshal(raw, &r) != nil {
			continue
		}
		c, ok := chains[key{r.Family, r.Table, r.Chain}]
		if !ok {
			continue
		}
		c.rules = append(c.rules, nftRule(r.Expr))
	}
	if len(order) == 0 {
		// No input base chain at all: nothing filters input.
		return InputFirewall{Source: SourceNftables, Manager: manager, unhooked: true,
			chains: []inChain{{policy: "accept"}}}, true
	}
	fw := InputFirewall{Source: SourceNftables, Manager: manager, named: map[string]inChain{}}
	base := map[key]bool{}
	for _, k := range order {
		fw.chains = append(fw.chains, *chains[k])
		base[k] = true
	}
	for k, c := range chains {
		if !base[k] {
			fw.named[chainKey(c.table, k.name)] = *c
		}
	}
	return fw, true
}

// nftRule reduces one rule's expression list.
func nftRule(exprs []map[string]json.RawMessage) inRule {
	r := inRule{verdict: "skip"}
	for _, e := range exprs {
		for kind, body := range e {
			switch kind {
			case "accept":
				r.verdict = "accept"
			case "drop":
				r.verdict = "drop"
			case "reject":
				r.verdict = "reject"
			case "return":
				r.verdict = "return"
			case "jump", "goto":
				var to struct{ Target string }
				if json.Unmarshal(body, &to) != nil || to.Target == "" {
					r.narrow = true
					continue
				}
				r.verdict, r.target = kind, to.Target
			case "xt":
				var xt struct{ Type, Name string }
				_ = json.Unmarshal(body, &xt) // an unreadable xt stays unjudged below
				switch {
				case xt.Type == "target" && xt.Name == "REJECT":
					r.verdict = "reject"
				case xt.Type == "target" && xt.Name == "DROP":
					r.verdict = "drop"
				case xt.Type == "match" && (xt.Name == "conntrack" || xt.Name == "state"):
					// iptables-nft's state match: its states are not in the
					// JSON. With a port it is the NEW-packets rule of a port;
					// without one it is the established catch-all.
					r.xtState = true
				case xt.Type == "match" && xt.Name == "addrtype":
					r.addrtype = true
				case xt.Type == "match" && (xt.Name == "tcp" || xt.Name == "udp" ||
					xt.Name == "multiport"):
				default:
					r.narrow = true
				}
			case "match":
				nftMatch(body, &r)
			}
		}
	}
	if r.xtState && len(r.ports) == 0 {
		r.narrow = true
	}
	return r
}

// nftMatch reduces one match expression.
func nftMatch(body json.RawMessage, r *inRule) {
	var m struct {
		Op    string          `json:"op"`
		Left  json.RawMessage `json:"left"`
		Right json.RawMessage `json:"right"`
	}
	if json.Unmarshal(body, &m) != nil {
		r.narrow = true
		return
	}
	var left struct {
		Payload *struct{ Protocol, Field string } `json:"payload"`
		Meta    *struct{ Key string }             `json:"meta"`
		Ct      *struct{ Key string }             `json:"ct"`
		Fib     *struct {
			Result string   `json:"result"`
			Flags  []string `json:"flags"`
		} `json:"fib"`
	}
	_ = json.Unmarshal(m.Left, &left) // an unreadable left side falls to the default: narrow
	negated := m.Op == "!="
	switch {
	case left.Payload != nil && left.Payload.Field == "dport" && !negated:
		r.proto = left.Payload.Protocol
		r.ports = nftPorts(m.Right)
	case left.Payload != nil && left.Payload.Protocol == "ip" && left.Payload.Field == "protocol":
		var proto string
		if json.Unmarshal(m.Right, &proto) == nil && (proto == "tcp" || proto == "udp") {
			r.proto = proto
		} else {
			r.narrow = true
		}
	case left.Meta != nil && left.Meta.Key == "l4proto":
		var proto string
		if json.Unmarshal(m.Right, &proto) == nil && (proto == "tcp" || proto == "udp") {
			r.proto = proto
		} else {
			r.narrow = true
		}
	case left.Fib != nil && left.Fib.Result == "type" && hasToken(left.Fib.Flags, "daddr") &&
		!negated && strings.Contains(string(m.Right), `"local"`):
		// fib daddr type local: a packet to this host's own address, which
		// is what a peer's is.
	case left.Ct != nil && left.Ct.Key == "state":
		if !strings.Contains(string(m.Right), "new") || negated {
			r.narrow = true
		}
	default:
		// An interface, an address, a mark: not a rule about everyone.
		r.narrow = true
	}
}

// nftPorts reads a port, a set of ports or a range from a match's right side.
func nftPorts(raw json.RawMessage) [][2]int {
	var n int
	if json.Unmarshal(raw, &n) == nil {
		return [][2]int{{n, n}}
	}
	var rng struct {
		Range [2]int `json:"range"`
	}
	if json.Unmarshal(raw, &rng) == nil && rng.Range[1] > 0 {
		return [][2]int{rng.Range}
	}
	var set struct {
		Set []json.RawMessage `json:"set"`
	}
	if json.Unmarshal(raw, &set) == nil {
		var out [][2]int
		for _, item := range set.Set {
			out = append(out, nftPorts(item)...)
		}
		return out
	}
	return nil
}
