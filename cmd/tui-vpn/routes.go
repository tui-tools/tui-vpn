package main

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-vpn/internal/wireguard"
)

// This file is `r` on the nodes screen: the routes a subnet router or an exit
// node advertises stay pending until an admin approves them, which used to
// mean typing `headscale nodes approve-routes` by hand.

// startApproveRoutes opens the routes dialog for a node, prefilled with every
// route it advertises plus what is already approved: the one-keystroke answer
// is "approve what it offers".
func (a *app) startApproveRoutes(node wireguard.Node) tea.Cmd {
	if !a.headscaleAnswers() {
		return nil
	}
	states := wireguard.NodeRoutes(node)
	if len(states) == 0 {
		a.setStatusf(ui.StatusInfo, "%s advertises no routes (tailscale up "+
			"--advertise-routes=… or --advertise-exit-node on it)", nodeName(node))
		return nil
	}
	var want []string
	for _, st := range states {
		if st.Advertised || st.Approved {
			want = append(want, st.Route)
		}
	}
	a.input = ui.NewInput("Routes of node "+node.ID+" ("+nodeName(node)+")",
		"198.51.100.0/24, exit", wireguard.RouteWords(want))
	a.input.Help = "Advertised: " + orDash(wireguard.RouteWords(node.AvailableRoutes)) +
		"\nApproved:   " + orDash(wireguard.RouteWords(node.ApprovedRoutes)) +
		"\n\nThe routes to approve, separated by commas. The list REPLACES the node's " +
		"approvals: take an entry out to revoke it, leave the line empty to revoke them " +
		"all. \"exit\" stands for 0.0.0.0/0 and ::/0 together: the node as an exit node."
	a.input.Payload = node.ID
	a.inputPurpose = inputApproveRoutes
	a.mode = modeInput
	return nil
}

// confirmApproveRoutes parses the answer and opens the confirm, saying what
// is approved and what is revoked.
func (a *app) confirmApproveRoutes(id, value string) tea.Cmd {
	routes, err := wireguard.ParseRouteList(value)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	var node wireguard.Node
	for _, n := range a.state.Headscale.Nodes {
		if n.ID == id {
			node = n
		}
	}
	approve, revoke := wireguard.RouteChange(node, routes)
	if len(approve) == 0 && len(revoke) == 0 {
		a.setStatus(ui.StatusInfo, "node "+id+" already has exactly these routes approved")
		return nil
	}
	lines := []string{}
	if len(approve) > 0 {
		lines = append(lines, "Approves: "+wireguard.RouteWords(approve))
	}
	if len(revoke) > 0 {
		lines = append(lines, "Revokes:  "+wireguard.RouteWords(revoke)+
			" — the tailnet stops reaching it through this node.")
	}
	var unadvertised []string
	advertised := map[string]bool{}
	for _, r := range node.AvailableRoutes {
		advertised[r] = true
	}
	for _, r := range approve {
		if !advertised[r] {
			unadvertised = append(unadvertised, r)
		}
	}
	if len(unadvertised) > 0 {
		lines = append(lines, "Note: "+wireguard.RouteWords(unadvertised)+" is not advertised "+
			"by the node; the approval waits until it is.")
	}
	lines = append(lines, "", "approve-routes sets the whole list: what is not in the "+
		"command below is not approved afterwards.")
	cmd, err := wireguard.BuildApproveRoutes(id, routes, len(revoke) > 0)
	return a.openConfirmWith(strings.Join(lines, "\n"), cmd, err)
}
