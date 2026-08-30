package main

import (
	"os"
	"os/user"
	"strings"
	"testing"

	"github.com/tui-tools/tui-kit/config"
)

// baseConfig is the configuration a report is rendered against: the defaults,
// with nothing read from disk or from the environment.
func baseConfig() config.Config {
	return config.Config{Tool: toolName, Values: defaults()}
}

// TestRunReportDemo checks the half of the block this tool owns under --demo:
// it says demo, names the imitated backends, and reads nothing off the host.
func TestRunReportDemo(t *testing.T) {
	var out strings.Builder
	opts := options{demo: true, report: true}
	if err := runReport(baseConfig(), opts, &out); err != nil {
		t.Fatalf("runReport: %v", err)
	}

	got := out.String()
	for _, want := range []string{
		"backend: demo\n",
		"mode: demo (sample data, the system was not read)\n",
		"demo backend: wireguard + headscale\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("report is missing %q:\n%s", want, got)
		}
	}
	if !strings.HasPrefix(got, toolName+" ") {
		t.Errorf("report should start with the tool name:\n%s", got)
	}
}

// TestRunReportLive names the backend the manifest declares, says the run was
// live, and carries the tool-specific facts.
func TestRunReportLive(t *testing.T) {
	var out strings.Builder
	if err := runReport(baseConfig(), options{report: true}, &out); err != nil {
		t.Fatalf("runReport: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"backend: " + backendName,
		"mode: live\n",
		"wireguard-tools: ",
		"headscale: ",
		"wg interfaces: ",
		"headscale server: ",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("report is missing %q:\n%s", want, got)
		}
	}
}

// TestRunReportKeepsItsPrivacyPromise is the assertion the bug form depends on:
// the block, pasted into a public issue, must carry no user name, home path or
// host name.
func TestRunReportKeepsItsPrivacyPromise(t *testing.T) {
	var out strings.Builder
	if err := runReport(baseConfig(), options{report: true}, &out); err != nil {
		t.Fatalf("runReport: %v", err)
	}
	got := out.String()

	if strings.Contains(got, "/home/") {
		t.Errorf("report carries a home path:\n%s", got)
	}
	if host, err := os.Hostname(); err == nil {
		assertAbsent(t, got, host, "host name")
	}
	if u, err := user.Current(); err == nil {
		assertAbsent(t, got, u.Username, "user name")
	}
}

// assertAbsent fails when name appears in a value of the block. The three
// values a name can legitimately collide with — the distribution, the kernel
// and the terminal, none of which this tool supplies — are skipped.
func assertAbsent(t *testing.T, block, name, what string) {
	t.Helper()
	if name == "" {
		return
	}
	for _, line := range strings.Split(block, "\n") {
		key, value, ok := strings.Cut(line, ": ")
		if !ok {
			key, value = "", line
		}
		if key == "distro" || key == "kernel" || key == "term" {
			continue
		}
		if strings.Contains(value, name) {
			t.Errorf("report carries the %s %q on %q", what, name, line)
		}
	}
}

// TestScrubHome covers the one value this tool passes into the block that could
// name its user: a backend-build error carrying a configured path.
func TestScrubHome(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"a home path", "/home/ana/wg is missing", "~elsewhere~ is missing"},
		{"root's home", "/root/wg is missing", "~elsewhere~ is missing"},
		{"a path that names nobody", "/etc/wireguard is missing", "/etc/wireguard is missing"},
		{"nothing to scrub", "wg was not found", "wg was not found"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := scrubHome(tc.in); got != tc.want {
				t.Errorf("scrubHome(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
