package wireguard

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/tui-tools/tui-kit/runner"
)

// This file is what the list screens say when headscale's CLI has nothing to
// answer. The CLI talks to the running server over a unix socket, so with the
// unit stopped every list fails — and it fails as JSON, because it was asked
// for JSON: `{`, a tab, `"error": "connecting to headscale: …"`, `}`. The
// status line keeps one line of an error, so what used to reach the screen was
// a lone `{`, right under a panel that already knew the unit was inactive.

// NotRunningMessage is what the users, nodes and keys screens show instead of
// reading the CLI, when the headscale unit is known not to be running, or ""
// when the CLI is worth asking. A unit systemd does not know at all (an
// is-enabled answer that could not be read) is not a reason to skip the read:
// headscale may be running outside systemd.
func NotRunningMessage(cp ControlPlane) string {
	switch cp.ServiceState {
	case "inactive", "failed":
	default:
		return ""
	}
	if cp.ServiceEnabled == "" || cp.ServiceEnabled == "unknown" {
		return ""
	}
	if cp.ServiceState == "failed" {
		return "headscale has failed · S reviews the settings and restarts it; " +
			"journalctl -u " + HeadscaleService + " says why"
	}
	if ControlPlaneConfigured(cp) {
		return "headscale is not running · systemctl start " + HeadscaleService +
			" starts it (S reviews the settings first)"
	}
	return "headscale is not running · S configures and starts it"
}

// ControlPlaneConfigured reports whether config.yaml has been set up for
// clients at all: a server_url that is not the stock loopback one. It is what
// decides whether a stopped unit needs S or only a start.
func ControlPlaneConfigured(cp ControlPlane) bool {
	return cp.Readable && cp.ServerURL != "" && !IsLoopbackHost(URLHost(cp.ServerURL))
}

// CLIErrorMessage turns a failed headscale CLI call into one line worth
// showing. Asked for `--output json`, the CLI prints its error as a JSON
// object; the line shown is that object's error (or message) field. Anything
// else falls back to the runner's own one-line error.
func CLIErrorMessage(output string, err error) string {
	if msg := jsonErrorField(output); msg != "" {
		return msg
	}
	if err != nil {
		if msg := jsonErrorField(err.Error()); msg != "" {
			return msg
		}
		return runner.FirstLine(err.Error())
	}
	return runner.FirstLine(strings.TrimSpace(output))
}

// jsonErrorField finds the first JSON object in s and returns its error or
// message field, whichever it has, case-insensitively.
func jsonErrorField(s string) string {
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return ""
	}
	var obj map[string]any
	if err := json.NewDecoder(bytes.NewReader([]byte(s[start:]))).Decode(&obj); err != nil {
		return ""
	}
	for _, want := range []string{"error", "message"} {
		for key, value := range obj {
			if strings.EqualFold(key, want) {
				if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
					return runner.FirstLine(strings.TrimSpace(text))
				}
			}
		}
	}
	return ""
}

// TailSteps is how many confirms the end of a configuration flow takes: the
// restart alone, or the enable and then the restart when the unit is running
// but disabled (see BuildEnableHeadscale). The step count in a flow's first
// dialog is its own steps plus these.
func TailSteps(cp ControlPlane) int {
	if ServiceNeedsEnable(cp.ServiceEnabled) && cp.ServiceState == "active" {
		return 2
	}
	return 1
}
