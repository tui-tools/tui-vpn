package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-vpn/internal/wireguard"
)

// selectNode moves the nodes screen's cursor onto a node by id.
func selectNode(t *testing.T, a *app, id string) {
	t.Helper()
	a.setScreen(wireguard.ScreenNodes)
	for i, n := range a.state.Headscale.Nodes {
		if n.ID == id {
			a.cursor[wireguard.ScreenNodes] = i
			return
		}
	}
	t.Fatalf("no node %s", id)
}

// TestApproveRoutes drives r on the demo's subnet router: the dialog is
// prefilled with everything it advertises, the confirm says what changes and
// previews approve-routes, and the node then serves its routes and is an
// approved exit node. Taking the list back to empty revokes everything, in a
// danger dialog.
func TestApproveRoutes(t *testing.T) {
	a := newTestApp(t)
	selectNode(t, a, "4")
	if view := a.View(); !strings.Contains(view, "ROUTES") ||
		!strings.Contains(view, "1/2 approved · exit pending") ||
		!strings.Contains(view, "routes of office-gw: 198.51.100.0/24 ✓ · 203.0.113.0/24 pending") {
		t.Errorf("the nodes screen does not show the routes:\n%s", view)
	}
	if got := wireguard.RoutesText(a.state.Headscale.Nodes[3]); !strings.Contains(got, "pending") {
		t.Errorf("the demo router should have routes pending: %q", got)
	}
	model, _ := a.Update(key("r"))
	a = model.(*app)
	if a.mode != modeInput || a.inputPurpose != inputApproveRoutes {
		t.Fatalf("r did not open the routes dialog (mode %d, loading %v)", a.mode, a.loading)
	}
	if got := a.input.Model.Value(); got != "198.51.100.0/24, 203.0.113.0/24, exit" {
		t.Errorf("prefill = %q, want every advertised route", got)
	}
	a = enter(t, a)
	if a.mode != modeConfirm {
		t.Fatalf("no confirm (status %q)", a.status)
	}
	if a.confirm.Command != "headscale nodes approve-routes --identifier 4 --routes "+
		"198.51.100.0/24,203.0.113.0/24,0.0.0.0/0,::/0" {
		t.Errorf("preview = %q", a.confirm.Command)
	}
	if !strings.Contains(a.confirm.Body, "Approves: 203.0.113.0/24, exit") || a.confirm.Danger {
		t.Errorf("body (danger %v):\n%s", a.confirm.Danger, a.confirm.Body)
	}
	a = confirmAndRun(t, a)
	state, _ := a.backend.Load(t.Context())
	a.state = state
	if got := wireguard.RoutesText(state.Headscale.Nodes[3]); got !=
		"198.51.100.0/24 ✓ · 203.0.113.0/24 ✓ · exit node ✓" {
		t.Errorf("after approving: %q", got)
	}

	// Revoking all: an empty line is an answer, and a dangerous one.
	selectNode(t, a, "4")
	model, _ = a.Update(key("r"))
	a = model.(*app)
	a.input.Model.SetValue("")
	a = enter(t, a)
	if !strings.HasSuffix(a.confirm.Command, "--routes=") || !a.confirm.Danger ||
		!strings.Contains(a.confirm.Body, "Revokes:") {
		t.Errorf("revoke all: %q (danger %v)\n%s", a.confirm.Command, a.confirm.Danger, a.confirm.Body)
	}
}

// TestRoutesOnANodeWithoutAny: r says there is nothing to approve, and does
// not reload; ctrl+r still reloads on the nodes screen.
func TestRoutesOnANodeWithoutAny(t *testing.T) {
	a := newTestApp(t)
	selectNode(t, a, "1")
	model, _ := a.Update(key("r"))
	a = model.(*app)
	if a.mode != modeBrowse || !strings.Contains(a.status, "advertises no routes") || a.loading {
		t.Errorf("mode %d, status %q, loading %v", a.mode, a.status, a.loading)
	}
	model, cmd := a.Update(tea.KeyMsg{Type: tea.KeyCtrlR})
	a = model.(*app)
	if cmd == nil || !a.loading {
		t.Error("ctrl+r did not reload on the nodes screen")
	}
}

// TestCheckCountsRoutes: --check reports each node's routes as counts, never
// the networks.
func TestCheckCountsRoutes(t *testing.T) {
	var out strings.Builder
	if err := runCheck(context.Background(), wireguard.NewFake(), nil, &out); err != nil {
		t.Fatal(err)
	}
	var report checkReport
	if err := json.Unmarshal([]byte(out.String()), &report); err != nil {
		t.Fatal(err)
	}
	routes := report.Headscale.NodeRoutes
	if len(routes) != 1 || routes[0].ID != "4" || routes[0].Advertised != 2 ||
		routes[0].Approved != 1 || routes[0].Pending != 1 || routes[0].ExitNode != "pending" {
		t.Errorf("nodeRoutes = %+v", routes)
	}
	if strings.Contains(out.String(), "203.0.113.0") || strings.Contains(out.String(), "0.0.0.0/0") {
		t.Error("--check printed a route")
	}
}
