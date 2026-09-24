package wireguard

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestNotRunningMessage(t *testing.T) {
	configured := ControlPlane{Readable: true, ServerURL: "http://203.0.113.10:443"}
	stock := ControlPlane{Readable: true, ServerURL: "http://127.0.0.1:8080"}
	for _, tc := range []struct {
		name            string
		cp              ControlPlane
		active, enabled string
		want            string
	}{
		{"running", stock, "active", "enabled", ""},
		{"starting", stock, "activating", "enabled", ""},
		{"fresh install", stock, "inactive", "disabled", "S configures and starts it"},
		{"configured, stopped", configured, "inactive", "enabled", "systemctl start headscale"},
		{"failed", configured, "failed", "enabled", "journalctl -u headscale"},
		// No unit at all: headscale may be running outside systemd.
		{"no unit", stock, "inactive", "unknown", ""},
		{"not read", stock, "", "", ""},
	} {
		tc.cp.ServiceState, tc.cp.ServiceEnabled = tc.active, tc.enabled
		got := NotRunningMessage(tc.cp)
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s: NotRunningMessage = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestCLIErrorMessage is the real case: asked for JSON, the CLI prints its
// error as a JSON object, and the one-line status used to show only "{".
func TestCLIErrorMessage(t *testing.T) {
	data, err := os.ReadFile("testdata/headscale-error-socket.json")
	if err != nil {
		t.Fatal(err)
	}
	wrapped := errors.New("`sudo -n headscale users list --output json` failed: {")
	got := CLIErrorMessage(string(data), wrapped)
	if !strings.HasPrefix(got, "connecting to headscale: ") || strings.Contains(got, "{") {
		t.Errorf("CLIErrorMessage = %q, want the JSON error field", got)
	}
	// Not JSON: the runner's own line.
	if got := CLIErrorMessage("permission denied\nmore", errors.New("`headscale` failed: permission denied")); got != "`headscale` failed: permission denied" {
		t.Errorf("CLIErrorMessage (plain) = %q", got)
	}
	// A message field, in another case, is taken too.
	if got := CLIErrorMessage(`{"Message": "boom"}`, nil); got != "boom" {
		t.Errorf("CLIErrorMessage (message) = %q", got)
	}
}

func TestTailSteps(t *testing.T) {
	for _, tc := range []struct {
		active, enabled string
		want            int
	}{
		{"active", "enabled", 1},
		{"inactive", "disabled", 1}, // enable --now is one step
		{"active", "disabled", 2},   // enable, then restart
		{"active", "static", 1},
	} {
		cp := ControlPlane{ServiceState: tc.active, ServiceEnabled: tc.enabled}
		if got := TailSteps(cp); got != tc.want {
			t.Errorf("TailSteps(%s, %s) = %d, want %d", tc.active, tc.enabled, got, tc.want)
		}
	}
}

// TestFakeWithTheUnitStopped: the demo answers like a real host whose unit is
// stopped — the configuration, and no lists.
func TestFakeWithTheUnitStopped(t *testing.T) {
	f := NewFake()
	f.SetService("inactive", "disabled")
	state, _ := f.Load(t.Context())
	hs := state.Headscale
	if !hs.NotRunning || hs.Error == "" || len(hs.Users) != 0 || len(hs.Nodes) != 0 {
		t.Errorf("stopped unit: notRunning=%v error=%q users=%d nodes=%d",
			hs.NotRunning, hs.Error, len(hs.Users), len(hs.Nodes))
	}
	if !hs.ControlPlane.Readable {
		t.Error("the configuration should still be read with the unit stopped")
	}
}
