package main

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-vpn/internal/wireguard"
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
	if err := a.draft.forward.Validate(); err != nil {
		a.askEgress(value, err)
		return nil
	}
	if _, _, err := wireguard.ForwardingRules(a.draft.address, *a.draft.forward); err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	return a.confirmKeygen()
}

// forwardExplanation is the paragraph above a forwarding server's conf: what
// each of its PostUp lines is for.
func forwardExplanation(f wireguard.ForwardSpec) string {
	to := "any destination"
	if len(f.Networks) > 0 {
		to = strings.Join(f.Networks, ", ")
	}
	return "Forwarding server for " + to + " through " + f.Egress + ". PostUp turns on " +
		"net.ipv4.ip_forward (left on at down: something else may rely on it), inserts FORWARD " +
		"rules with -I — a FORWARD chain that ends in REJECT would never reach an appended " +
		"rule — accepts the return path by connection tracking only, and masquerades the " +
		"peers behind " + f.Egress + ". PostDown removes the rules."
}

// portVerdictFor is what the host firewall does with a handshake to port.
func (a *app) portVerdictFor(port int) wireguard.Verdict {
	return a.state.Firewall.UDPPortVerdict(port)
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
	open, err := wireguard.BuildOpenListenPort(port)
	lines := []string{fmt.Sprintf("Step 3 of %d (optional) — open udp/%d, or no handshake "+
		"reaches %s.", a.wizardSteps(), port, name)}
	switch a.portVerdictFor(port) {
	case wireguard.VerdictUnknown:
		lines = append(lines, "The host firewall could not be read ("+
			orDash(a.state.Firewall.Error)+"), so this is offered in case it is closed.")
	default:
		lines = append(lines, fmt.Sprintf("The host firewall's INPUT chain does not accept "+
			"udp/%d now (%s). Cloud images often end INPUT in a REJECT rule — the "+
			"provider's Ubuntu image on Oracle Cloud does — so the port stays closed even "+
			"with the cloud's own security list open; -I puts this rule above that REJECT.",
			port, a.portVerdictFor(port)))
	}
	lines = append(lines, "This rule is NOT persisted: it is gone at the next reboot or "+
		"firewall reload.")
	if a.state.TUIFirewall {
		lines = append(lines, "tui-firewall is installed: open udp/"+strconv.Itoa(port)+
			" there to make it permanent (it has no non-interactive mode, so this tool does "+
			"not drive it).")
	} else {
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
