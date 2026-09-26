package main

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-wireguard/internal/wireguard"
)

// This file is the part of the new-interface wizard that makes a WireGuard
// server usable: forwarding for the networks behind it, and its listen port
// open in the host firewall. On a cloud image whose INPUT and FORWARD chains
// end in REJECT, an interface created without either takes no handshake and
// forwards nothing, and nothing on screen says why.

// The role picker's options.
const (
	roleEndpoint  = "endpoint — peers reach this host only"
	roleForwarder = "forwarding server — peers reach networks behind this host (forwarding + NAT)"
)

// wizardTookRole records the role and, for a forwarding server, asks which
// networks it forwards for.
func (a *app) wizardTookRole(choice string) tea.Cmd {
	if choice != roleForwarder {
		a.draft.forward = nil
		return a.confirmKeygen()
	}
	a.draft.forward = &wireguard.ForwardSpec{}
	a.askNetworks(strings.Join(wireguard.ForwardCandidates(a.state.Routes, a.wgDevices()), ", "), nil)
	return nil
}

// wgDevices is the set of WireGuard interfaces, which are never a network to
// forward to or a way out.
func (a *app) wgDevices() map[string]bool {
	skip := map[string]bool{a.draft.name: true, "lo": true}
	for _, d := range a.state.Devices {
		skip[d.Name] = true
	}
	return skip
}

// askNetworks opens the "forwards traffic for" step.
func (a *app) askNetworks(value string, problem error) {
	help := "The networks peers reach through this interface, in CIDR form (IPv4), " +
		"separated by commas. Proposed: this host's own networks from its routing table. " +
		"Empty forwards to any destination (a full tunnel)."
	a.openRetry(inputNewIfaceNetworks, "New interface — forwards traffic for",
		"10.0.0.0/16", value, help, problem)
}

// wizardTookNetworks validates the networks and asks for the egress NIC.
func (a *app) wizardTookNetworks(value string) tea.Cmd {
	networks, err := wireguard.ParseNetworks(value)
	if err != nil {
		a.askNetworks(value, err)
		return nil
	}
	a.draft.forward.Networks = networks
	a.askEgress(wireguard.DefaultRouteDevice(a.state.Routes), nil)
	return nil
}

// askEgress opens the egress NIC step.
func (a *app) askEgress(value string, problem error) {
	a.openRetry(inputNewIfaceEgress, "New interface — egress interface", "eth0", value,
		"The NIC forwarded traffic leaves by, and is masqueraded behind. Proposed: the "+
			"device of the default route.", problem)
}

// wizardTookEgress validates the egress and opens the keygen.
func (a *app) wizardTookEgress(value string) tea.Cmd {
	a.draft.forward.Egress = value
	a.draft.forward.Manager, a.draft.forward.EgressZone, a.draft.forward.BindZone = "", "", ""
	if fwd := a.state.Firewalld; fwd.Running {
		// firewalld is in charge of forwarding: an iptables FORWARD accept
		// would be overruled by its own forward chain (issue #30).
		a.draft.forward.Manager = wireguard.ManagerFirewalld
		a.draft.forward.EgressZone = fwd.ZoneOf(value)
		// firewalld dispatches no policy between two interfaces that are
		// both only in the default zone's catch-all. When the egress NIC is
		// bound (NetworkManager binds the NICs it manages) the policy is
		// dispatched on it and nothing needs binding; otherwise the
		// WireGuard interface is bound to the zone it falls into anyway.
		if fwd.BoundZone(a.draft.name) == "" && fwd.BoundZone(value) == "" {
			a.draft.forward.BindZone = fwd.DefaultZone()
		}
	}
	if err := a.draft.forward.Validate(); err != nil {
		a.askEgress(value, err)
		return nil
	}
	if _, _, err := wireguard.ForwardingRules(a.draft.name, a.draft.address, *a.draft.forward); err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	return a.confirmKeygen()
}

// forwardExplanation is the paragraph above a forwarding server's conf: what
// each of its PostUp lines is for.
func forwardExplanation(name string, f wireguard.ForwardSpec) string {
	to := "any destination"
	if len(f.Networks) > 0 {
		to = strings.Join(f.Networks, ", ")
	}
	if f.Manager == wireguard.ManagerFirewalld {
		policy, _ := wireguard.FirewalldPolicyName(name)
		return "Forwarding server for " + to + " through " + f.Egress + ", on a host where " +
			"firewalld is in charge: an iptables FORWARD rule would be overruled by firewalld's " +
			"own forward chain, so PostUp builds the firewalld policy " + policy + " instead. " +
			"It forwards from the peers' network (ingress ANY, matched by source) to zone " +
			f.EgressZone + " (" + f.Egress + "'s zone) and masquerades it there; the return " +
			"path is firewalld's own established/related accept. " + bindText(name, f) +
			"PostUp also turns on " +
			"net.ipv4.ip_forward (left on at down). Policies exist only in firewalld's " +
			"permanent configuration, so PostUp and PostDown end in firewall-cmd --reload, " +
			"which also drops any runtime-only firewalld change made without --permanent. " +
			"PostDown deletes the policy, and its rules with it."
	}
	return "Forwarding server for " + to + " through " + f.Egress + ". PostUp turns on " +
		"net.ipv4.ip_forward (left on at down: something else may rely on it), inserts FORWARD " +
		"rules with -I — a FORWARD chain that ends in REJECT would never reach an appended " +
		"rule — accepts the return path by connection tracking only, and masquerades the " +
		"peers behind " + f.Egress + ". PostDown removes the rules."
}

// bindText explains the zone binding of the WireGuard interface, when PostUp
// makes one.
func bindText(name string, f wireguard.ForwardSpec) string {
	if f.BindZone == "" {
		return ""
	}
	return name + " is bound to zone " + f.BindZone + ", the zone it falls into anyway, so " +
		"firewalld has an interface to dispatch the policy on (" + f.Egress + " is not bound to " +
		"a zone either, and between two interfaces in the default zone's catch-all firewalld " +
		"applies no policy); PostDown unbinds it. "
}

// firewalldForwarder reports that the interface being created is a
// forwarding server whose rules are a firewalld policy.
func (a *app) firewalldForwarder() bool {
	return a.draft.forward != nil && a.draft.forward.Manager == wireguard.ManagerFirewalld
}

// portVerdictFor is what the host firewall does with a handshake to port.
func (a *app) portVerdictFor(port int) wireguard.Verdict {
	return a.state.Input.UDPVerdict(port)
}

// needsPortStep reports whether the wizard offers to open the listen port:
// whenever the firewall does not already accept it, unknown included.
func (a *app) needsPortStep() bool {
	port, _ := strconv.Atoi(a.draft.port)
	return a.portVerdictFor(port) != wireguard.VerdictAccept
}

// wizardSteps is how many confirms the wizard takes: keygen, conf, the port
// when it is not open yet, and the optional up.
func (a *app) wizardSteps() int {
	if a.needsPortStep() {
		return 4
	}
	return 3
}

// confirmOpenPort offers the runtime rule that opens the listen port, and
// says what it cannot do: survive a reboot. When tui-firewall is installed,
// it is named as the way to make it permanent; it has no non-interactive
// mode, so this tool does not drive it.
func (a *app) confirmOpenPort(name string, port int) tea.Cmd {
	input := a.state.Input
	open, err := wireguard.BuildOpenListenPortFor(input.Manager, port)
	if a.firewalldForwarder() {
		// The interface's PostUp reloads firewalld, which would drop a
		// runtime-only port the moment it comes up.
		open, err = wireguard.BuildOpenListenPortPermanent(port)
	}
	lines := []string{fmt.Sprintf("Step 3 of %d (optional) — open udp/%d, or no handshake "+
		"reaches %s.", a.wizardSteps(), port, name)}
	switch {
	case a.portVerdictFor(port) == wireguard.VerdictUnknown && input.Source == "":
		lines = append(lines, "The host firewall could not be read ("+
			orDash(input.Error)+"), so this is offered in case it is closed.")
	case a.portVerdictFor(port) == wireguard.VerdictUnknown:
		lines = append(lines, fmt.Sprintf("The host firewall (read from %s) has rules this "+
			"tool cannot judge for udp/%d, so this is offered in case it is closed.",
			input.Source, port))
	case input.Manager == wireguard.ManagerFirewalld:
		lines = append(lines, fmt.Sprintf("firewalld does not allow udp/%d now (%s, read "+
			"from %s). It rejects in its own nftables table whatever its zones do not "+
			"allow, so the port is added to its zone with firewall-cmd.",
			port, a.portVerdictFor(port), input.Source))
	default:
		lines = append(lines, fmt.Sprintf("The host firewall does not accept udp/%d now "+
			"(%s, read from %s). Cloud images often end INPUT in a REJECT rule — the "+
			"provider's Ubuntu image on Oracle Cloud does — so the port stays closed even "+
			"with the cloud's own security list open; -I puts this rule above that REJECT.",
			port, a.portVerdictFor(port), input.Source))
	}
	switch {
	case a.firewalldForwarder():
		lines = append(lines, "This one goes into firewalld's permanent configuration, not "+
			"the running one: "+name+"'s PostUp ends in firewall-cmd --reload, which would "+
			"drop a runtime-only port. It takes effect at that reload when "+name+" comes up, "+
			"and stays after down (firewall-cmd --permanent --remove-port="+
			strconv.Itoa(port)+"/udp removes it).")
	case input.Manager == wireguard.ManagerFirewalld:
		lines = append(lines, "This is NOT persisted: it is gone at the next reboot or "+
			"firewall-cmd --reload.")
	default:
		lines = append(lines, "This rule is NOT persisted: it is gone at the next reboot or "+
			"firewall reload.")
	}
	switch {
	case a.firewalldForwarder():
		// Already said: the port is permanent.
	case a.state.TUIFirewall:
		lines = append(lines, "tui-firewall is installed: open udp/"+strconv.Itoa(port)+
			" there to make it permanent (it has no non-interactive mode, so this tool does "+
			"not drive it).")
	case input.Manager == wireguard.ManagerFirewalld:
		lines = append(lines, "To keep it, run the same with --permanent as well "+
			"(firewall-cmd --permanent --add-port="+strconv.Itoa(port)+"/udp), or install "+
			"tui-firewall and open the port there.")
	case input.Manager == wireguard.ManagerUFW:
		lines = append(lines, "To keep it, allow it in ufw (ufw allow "+strconv.Itoa(port)+
			"/udp), or install tui-firewall and open the port there.")
	default:
		lines = append(lines, "To keep it, save the ruleset (netfilter-persistent save), or "+
			"install tui-firewall and open the port there.")
	}
	lines = append(lines, "Esc leaves the port as it is and the interface down.")
	cmd := a.openConfirmWith(strings.Join(lines, "\n"), open, err)
	if a.mode == modeConfirm {
		a.after = func(string) tea.Cmd { return a.confirmOfferUp(name) }
	}
	return cmd
}

// firewallText renders an interface's listen-port verdict for the table.
func firewallText(d wireguard.Device) string {
	if d.ListenPort == 0 {
		return "-"
	}
	switch d.PortVerdict {
	case wireguard.VerdictAccept:
		return "open"
	case wireguard.VerdictReject, wireguard.VerdictDrop:
		return "closed"
	}
	return "?"
}
