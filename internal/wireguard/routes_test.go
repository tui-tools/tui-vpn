package wireguard

import (
	"reflect"
	"strings"
	"testing"
)

// TestParseNodesRoutes reads the route lists in the shape headscale 0.29
// prints them: snake_case, integer ids, protobuf timestamps, and each list
// omitted when it is empty.
func TestParseNodesRoutes(t *testing.T) {
	nodes, err := ParseNodes([]byte(readFixture(t, "headscale-nodes-0.29.json")))
	if err != nil || len(nodes) != 2 {
		t.Fatalf("ParseNodes = %d nodes, %v", len(nodes), err)
	}
	if n := nodes[0]; n.ID != "1" || n.RegisterMethod != "oidc" || n.LastSeen.IsZero() ||
		len(n.AvailableRoutes) != 0 || RoutesText(n) != "-" {
		t.Errorf("a node with no routes: %+v", n)
	}
	gw := nodes[1]
	if !reflect.DeepEqual(gw.AvailableRoutes, []string{"198.51.100.0/24", "203.0.113.0/24", "0.0.0.0/0", "::/0"}) ||
		!reflect.DeepEqual(gw.ApprovedRoutes, []string{"198.51.100.0/24"}) ||
		!reflect.DeepEqual(gw.SubnetRoutes, []string{"198.51.100.0/24"}) {
		t.Errorf("routes = %+v", gw)
	}
	if got := RoutesText(gw); got != "198.51.100.0/24 ✓ · 203.0.113.0/24 pending · exit node pending" {
		t.Errorf("RoutesText = %q", got)
	}
	if got := RoutesSummary(gw); got != "1/2 approved · exit pending" {
		t.Errorf("RoutesSummary = %q", got)
	}
	if ExitNodeState(gw) != "pending" {
		t.Errorf("ExitNodeState = %q", ExitNodeState(gw))
	}
	gw.ApprovedRoutes = append(gw.ApprovedRoutes, ExitRoutes...)
	if ExitNodeState(gw) != "approved" || !strings.HasSuffix(RoutesText(gw), "exit node ✓") {
		t.Errorf("approved exit node: %q", RoutesText(gw))
	}
	// An approval for a route the node stopped advertising is shown as such.
	stale := Node{ApprovedRoutes: []string{"192.0.2.0/24"}}
	if got := RoutesText(stale); got != "192.0.2.0/24 (approved, not advertised)" {
		t.Errorf("stale approval = %q", got)
	}
}

func TestParseRouteList(t *testing.T) {
	got, err := ParseRouteList("198.51.100.7/24, exit 203.0.113.0/24 exit")
	want := []string{"198.51.100.0/24", "0.0.0.0/0", "::/0", "203.0.113.0/24"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("ParseRouteList = %q, %v", got, err)
	}
	if got, err := ParseRouteList(""); err != nil || len(got) != 0 {
		t.Errorf("empty = %q, %v", got, err)
	}
	if _, err := ParseRouteList("198.51.100.0/24 --routes"); err == nil {
		t.Error("a flag was accepted as a route")
	}
	if got := RouteWords(want); got != "198.51.100.0/24, exit, 203.0.113.0/24" {
		t.Errorf("RouteWords = %q", got)
	}
}

func TestRouteChangeAndCommand(t *testing.T) {
	n := Node{ID: "4", AvailableRoutes: []string{"198.51.100.0/24", "203.0.113.0/24"},
		ApprovedRoutes: []string{"198.51.100.0/24"}}
	approve, revoke := RouteChange(n, []string{"203.0.113.0/24"})
	if !reflect.DeepEqual(approve, []string{"203.0.113.0/24"}) ||
		!reflect.DeepEqual(revoke, []string{"198.51.100.0/24"}) {
		t.Errorf("RouteChange = %q, %q", approve, revoke)
	}
	cmd, err := BuildApproveRoutes("4", []string{"198.51.100.0/24", "0.0.0.0/0", "::/0"}, false)
	if err != nil || cmd.String() != "headscale nodes approve-routes --identifier 4 --routes 198.51.100.0/24,0.0.0.0/0,::/0" ||
		cmd.Destructive {
		t.Errorf("BuildApproveRoutes = %q, %v", cmd.String(), err)
	}
	cmd, _ = BuildApproveRoutes("4", nil, true)
	if cmd.String() != "headscale nodes approve-routes --identifier 4 --routes=" || !cmd.Destructive {
		t.Errorf("revoke all = %q (destructive %v)", cmd.String(), cmd.Destructive)
	}
	if _, err := BuildApproveRoutes("x", nil, false); err == nil {
		t.Error("a non-numeric id was accepted")
	}
}

// TestFakeApprovesRoutes: the demo serves what is both advertised and
// approved, like headscale.
func TestFakeApprovesRoutes(t *testing.T) {
	f := NewFake()
	cmd, _ := BuildApproveRoutes("4", []string{"198.51.100.0/24", "203.0.113.0/24", "0.0.0.0/0", "::/0"}, false)
	if _, err := f.Run(t.Context(), cmd); err != nil {
		t.Fatal(err)
	}
	state, _ := f.Load(t.Context())
	for _, n := range state.Headscale.Nodes {
		if n.ID == "4" && (len(n.SubnetRoutes) != 4 || ExitNodeState(n) != "approved") {
			t.Errorf("after approving everything: %+v", n)
		}
	}
}
