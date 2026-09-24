package wireguard

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/tui-tools/tui-kit/runner"
)

// This file is the subnet-router half of the nodes screen. A node that runs
// `tailscale up --advertise-routes=…` (or --advertise-exit-node) offers routes
// to the tailnet, and they stay pending until an admin approves them. Since
// headscale 0.26 that is `headscale nodes approve-routes`, which SETS the
// node's approved list: every route not in it is revoked. The old `headscale
// routes` commands no longer exist.
//
// headscale 0.29 reports three lists per node in `nodes list --output json`,
// each omitted when empty: available_routes (what the node advertises),
// approved_routes (what an admin approved) and subnet_routes (the two
// together: what is actually served).

// ExitRoutes are the two routes an exit node advertises. They are approved
// together, and shown as one "exit node" rather than as two CIDRs.
var ExitRoutes = []string{"0.0.0.0/0", "::/0"}

// IsExitRoute reports whether r is one of the exit-node routes.
func IsExitRoute(r string) bool { return r == ExitRoutes[0] || r == ExitRoutes[1] }

// RouteState is one advertised or approved route and where it stands.
type RouteState struct {
	Route      string
	Advertised bool
	Approved   bool
}

// NodeRoutes lists a node's routes in a stable order: advertised ones first,
// in the node's order, then approvals for routes the node no longer
// advertises (stale, and harmless: nothing is served without both).
func NodeRoutes(n Node) []RouteState {
	approved := map[string]bool{}
	for _, r := range n.ApprovedRoutes {
		approved[r] = true
	}
	seen := map[string]bool{}
	var out []RouteState
	for _, r := range n.AvailableRoutes {
		if !seen[r] {
			seen[r] = true
			out = append(out, RouteState{Route: r, Advertised: true, Approved: approved[r]})
		}
	}
	for _, r := range n.ApprovedRoutes {
		if !seen[r] {
			seen[r] = true
			out = append(out, RouteState{Route: r, Approved: true})
		}
	}
	return out
}

// ExitNodeState says where a node stands as an exit node: "" when it does not
// advertise one, "approved" when both exit routes are approved, and
// "pending" otherwise.
func ExitNodeState(n Node) string {
	advertised, approved := 0, 0
	for _, r := range NodeRoutes(n) {
		if !IsExitRoute(r.Route) {
			continue
		}
		if r.Advertised {
			advertised++
		}
		if r.Approved && r.Advertised {
			approved++
		}
	}
	switch {
	case advertised == 0:
		return ""
	case approved == advertised:
		return "approved"
	}
	return "pending"
}

// RoutesText renders a node's routes for the table: each subnet route with
// its state, and the exit routes as one "exit node".
func RoutesText(n Node) string {
	var parts []string
	for _, r := range NodeRoutes(n) {
		if IsExitRoute(r.Route) {
			continue
		}
		switch {
		case r.Advertised && r.Approved:
			parts = append(parts, r.Route+" ✓")
		case r.Advertised:
			parts = append(parts, r.Route+" pending")
		default:
			parts = append(parts, r.Route+" (approved, not advertised)")
		}
	}
	if exit := ExitNodeState(n); exit != "" {
		if exit == "approved" {
			parts = append(parts, "exit node ✓")
		} else {
			parts = append(parts, "exit node pending")
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " · ")
}

// RoutesSummary is RoutesText short enough for a table cell: how many of the
// advertised subnet routes are approved, and the exit node's state. The
// routes themselves are spelled out for the selected node.
func RoutesSummary(n Node) string {
	advertised, approved := 0, 0
	for _, r := range NodeRoutes(n) {
		if IsExitRoute(r.Route) || !r.Advertised {
			continue
		}
		advertised++
		if r.Approved {
			approved++
		}
	}
	var parts []string
	if advertised > 0 {
		parts = append(parts, fmt.Sprintf("%d/%d approved", approved, advertised))
	}
	switch ExitNodeState(n) {
	case "approved":
		parts = append(parts, "exit ✓")
	case "pending":
		parts = append(parts, "exit pending")
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " · ")
}

// RouteWords renders a route list the way the approve dialog takes it back:
// CIDRs, with the exit routes as the single word "exit".
func RouteWords(routes []string) string {
	var words []string
	exit := false
	for _, r := range routes {
		if IsExitRoute(r) {
			if !exit {
				words = append(words, "exit")
				exit = true
			}
			continue
		}
		words = append(words, r)
	}
	return strings.Join(words, ", ")
}

// ParseRouteList reads the approve dialog's answer: CIDRs separated by commas
// or spaces, and "exit" for both exit-node routes. Each route is normalised
// to its network address, the form a node advertises.
func ParseRouteList(s string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(r string) {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	for _, word := range SplitList(s) {
		if strings.EqualFold(word, "exit") {
			for _, r := range ExitRoutes {
				add(r)
			}
			continue
		}
		prefix, err := netip.ParsePrefix(word)
		if err != nil {
			return nil, fmt.Errorf("not a route in CIDR form (or \"exit\"): %q", word)
		}
		add(prefix.Masked().String())
	}
	return out, nil
}

// RouteChange compares the approvals a node has with the ones asked for.
func RouteChange(n Node, want []string) (approve, revoke []string) {
	has := map[string]bool{}
	for _, r := range n.ApprovedRoutes {
		has[r] = true
	}
	wanted := map[string]bool{}
	for _, r := range want {
		wanted[r] = true
		if !has[r] {
			approve = append(approve, r)
		}
	}
	for _, r := range n.ApprovedRoutes {
		if !wanted[r] {
			revoke = append(revoke, r)
		}
	}
	return approve, revoke
}

// BuildApproveRoutes assembles `headscale nodes approve-routes`. The list
// replaces the node's approvals, so an empty one revokes them all: it is
// written `--routes=` so the preview shows the empty value rather than
// hiding an empty argument.
func BuildApproveRoutes(nodeID string, routes []string, revokes bool) (runner.Command, error) {
	if !validID(nodeID) {
		return runner.Command{}, fmt.Errorf("not a valid node id: %q", nodeID)
	}
	for _, r := range routes {
		if _, err := netip.ParsePrefix(r); err != nil {
			return runner.Command{}, fmt.Errorf("not a valid route: %q", r)
		}
	}
	argv := []string{"headscale", "nodes", "approve-routes", "--identifier", nodeID}
	if len(routes) == 0 {
		argv = append(argv, "--routes=")
	} else {
		argv = append(argv, "--routes", strings.Join(routes, ","))
	}
	desc := "Approve routes of node " + nodeID
	if len(routes) == 0 {
		desc = "Revoke every route of node " + nodeID
	}
	return runner.Command{Argv: argv, Description: desc, Destructive: revokes}, nil
}
