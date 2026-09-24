package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-vpn/internal/wireguard"
)

// startForwardingServer drives N up to the role picker for wg9 on port.
func startForwardingServer(t *testing.T, a *app, port string) *app {
	t.Helper()
	a.setScreen(wireguard.ScreenStatus)
	model, _ := a.Update(key("N"))
	a = model.(*app)
	a = typeAndEnter(t, a, "wg9")
	a = typeAndEnter(t, a, "192.0.2.129/25")
	a = clearAndType(t, a, port)
	return pick(t, a, roleForwarder)
}

// TestCreateForwardingServer is the real case end to end: a server whose
// peers reach the network behind it, on a host whose INPUT and FORWARD chains
// end in REJECT. The wizard proposes the networks and the egress from the
// routing table, writes the forwarding rules into the conf (previewed whole),
// offers the listen port, and the interface comes up forwarding.
func TestCreateForwardingServer(t *testing.T) {
	a := newTestApp(t)
	a = startForwardingServer(t, a, "51821")
	if a.inputPurpose != inputNewIfaceNetworks || a.input.Model.Value() != "198.51.100.0/24" {
		t.Fatalf("networks step: purpose %d, proposed %q (want the host's own network, "+
			"not wg0's or a link that is down)", a.inputPurpose, a.input.Model.Value())
	}
	a = enter(t, a)
	if a.inputPurpose != inputNewIfaceEgress || a.input.Model.Value() != "eth0" {
		t.Fatalf("egress step: purpose %d, proposed %q", a.inputPurpose, a.input.Model.Value())
	}
	a = enter(t, a)

	if !strings.Contains(a.confirm.Body, "Step 1 of 4") {
		t.Errorf("the port step is not counted:\n%s", a.confirm.Body)
	}
	a = confirmAndRun(t, a) // keygen
	body := a.confirm.Body
	for _, want := range []string{
		"PostUp = sysctl -w net.ipv4.ip_forward=1",
		"PostUp = iptables -I FORWARD -i %i -o eth0 -d 198.51.100.0/24 -j ACCEPT",
		"PostUp = iptables -I FORWARD -i eth0 -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"PostUp = iptables -t nat -I POSTROUTING -s 192.0.2.128/25 -o eth0 -d 198.51.100.0/24 -j MASQUERADE",
		"PostDown = iptables -D FORWARD -i %i -o eth0 -d 198.51.100.0/24 -j ACCEPT",
		"inserts FORWARD rules with -I",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the conf step is missing %q:\n%s", want, body)
		}
	}
	a = confirmAndRun(t, a) // conf

	if a.confirm.Command != "iptables -I INPUT -p udp --dport 51821 -j ACCEPT" {
		t.Fatalf("port step preview = %q", a.confirm.Command)
	}
	for _, want := range []string{"Step 3 of 4", "NOT persisted", "REJECT", "Oracle Cloud",
		"netfilter-persistent"} {
		if !strings.Contains(a.confirm.Body, want) {
			t.Errorf("the port step is missing %q:\n%s", want, a.confirm.Body)
		}
	}
	a = confirmAndRun(t, a) // port
	if !strings.Contains(a.confirm.Command, "wg-quick up wg9") ||
		!strings.Contains(a.confirm.Body, "Step 4 of 4") {
		t.Fatalf("up step: %q\n%s", a.confirm.Command, a.confirm.Body)
	}
	a = confirmAndRun(t, a)

	state, _ := a.backend.Load(t.Context())
	dev, ok := state.Device("wg9")
	if !ok || !dev.Forwarding || dev.PortVerdict != wireguard.VerdictAccept {
		t.Errorf("wg9 after the wizard: %+v", dev)
	}
	a.state = state
	if view := a.View(); !strings.Contains(view, "FORWARD") || !strings.Contains(view, "UDP IN") {
		t.Errorf("the interfaces table does not show the firewall columns:\n%s", view)
	}
}

// TestPortStepNamesTUIFirewall: with tui-firewall installed, the port step
// says to make the rule permanent there, since it cannot be driven.
func TestPortStepNamesTUIFirewall(t *testing.T) {
	a := newTestApp(t)
	a.state.TUIFirewall = true
	a = startForwardingServer(t, a, "51821")
	a = enter(t, a)
	a = enter(t, a)
	a = confirmAndRun(t, a)
	a = confirmAndRun(t, a)
	if !strings.Contains(a.confirm.Body, "tui-firewall is installed") {
		t.Errorf("the port step does not name tui-firewall:\n%s", a.confirm.Body)
	}
}

// TestOpenPortIsSkipped: a port the firewall already accepts is not offered,
// and the count says three steps.
func TestOpenPortIsSkipped(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenStatus)
	model, _ := a.Update(key("N"))
	a = model.(*app)
	a = typeAndEnter(t, a, "wg9")
	a = typeAndEnter(t, a, "192.0.2.129/25")
	a = enter(t, a) // 51820, which the demo firewall accepts
	a = pick(t, a, roleEndpoint)
	if !strings.Contains(a.confirm.Body, "Step 1 of 3") {
		t.Errorf("an open port was still counted:\n%s", a.confirm.Body)
	}
}

// TestNetworksStepRefusesIPv6: the rules are iptables, so an IPv6 network is
// refused at its step, which reopens with the reason.
func TestNetworksStepRefusesIPv6(t *testing.T) {
	a := newTestApp(t)
	a = startForwardingServer(t, a, "51821")
	a = clearAndType(t, a, "2001:db8::/32")
	if a.inputPurpose != inputNewIfaceNetworks || !strings.Contains(a.input.Help, "IPv6") {
		t.Errorf("IPv6 was not refused: purpose %d\n%s", a.inputPurpose, a.input.Help)
	}
	// Empty is an answer: any destination.
	a.input.Model.SetValue("")
	model, _ := a.Update(tea.KeyMsg{Type: tea.KeyEnter})
	a = model.(*app)
	if a.inputPurpose != inputNewIfaceEgress {
		t.Errorf("an empty network list did not move on (purpose %d)", a.inputPurpose)
	}
}

// TestCheckReportsTheListenPortAndForwarding: --check says, per interface,
// what INPUT does with a handshake and whether the host forwards for it.
func TestCheckReportsTheListenPortAndForwarding(t *testing.T) {
	var out strings.Builder
	if err := runCheck(context.Background(), wireguard.NewFake(), nil, &out); err != nil {
		t.Fatal(err)
	}
	var report checkReport
	if err := json.Unmarshal([]byte(out.String()), &report); err != nil {
		t.Fatal(err)
	}
	wg := report.WireGuard
	if !wg.FirewallChecked || len(wg.Interfaces) != 1 ||
		wg.Interfaces[0].ListenPortInput != wireguard.VerdictAccept || !wg.Interfaces[0].Forwarding {
		t.Errorf("wireguard summary = %+v", wg)
	}
	if strings.Contains(out.String(), "198.51.100.") {
		t.Error("--check printed a network of the host")
	}
}
