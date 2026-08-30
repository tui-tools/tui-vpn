package main

import (
	"context"
	"fmt"
	"regexp"
	"strconv"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/config"
	"github.com/tui-tools/tui-kit/report"
	"github.com/tui-tools/tui-kit/runner"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-vpn/internal/wireguard"
	"io"
)

// backendName is the backend the header names first: the WireGuard side.
const backendName = "wireguard"

// runReport prints the block a bug report needs and exits. Everything generic —
// the kit version, the distribution, the kernel, the terminal — is collected by
// the kit; what this tool adds is the part only it knows: the versions of the
// two backends it drives, whether this host runs a WireGuard interface, and
// whether a Headscale control plane is present.
//
// PRIVACY: it never prints a private key, a public key of this host, or an
// endpoint address. It reports counts and presence, nothing that identifies the
// network on the wire. It reads nothing privileged, and runs before the backend
// is required, so a host with nothing installed still produces a usable block.
func runReport(cfg config.Config, opts options, out io.Writer) error {
	palette, _ := theme.ResolvePalette()

	backends := probeCompat(context.Background(), opts.demo)
	wgCompat, _ := compatFor(backends, backendWG)
	hsCompat, _ := compatFor(backends, backendHeadscale)

	var backendError string
	if _, err := pickBackend(cfg, opts); err != nil {
		backendError = err.Error()
	}

	info := report.Info{
		Tool:           toolName,
		Version:        version,
		Backend:        backendName,
		BackendVersion: wgCompat.Version,
		BackendDetail:  wgCompat.Detail,
		Demo:           opts.demo,
		Sudo:           cfg.String(config.KeySudo, ""),
		Theme:          palette.Name,
	}

	if opts.demo {
		// The fake imitates the real backends; the versions on screen are not
		// this host's, so no host fact is probed under --demo.
		info.Backend = "demo"
		info.Extra = append(info.Extra,
			report.Field{Key: "demo backend", Value: "wireguard + headscale"})
	} else {
		facts := wireguard.HostFacts(context.Background(), cfg.SudoPrefix())
		info.Extra = append(info.Extra,
			report.Field{Key: "wireguard-tools", Value: versionLine("wg", searchWG, wgCompat)},
			report.Field{Key: "headscale", Value: versionLine("headscale", searchHeadscale, hsCompat)},
			report.Field{Key: "wg interfaces", Value: interfacesLine(facts.WGInterfaces)},
			report.Field{Key: "headscale server", Value: presentLine(facts.HeadscalePresent)},
		)
	}

	if backendError != "" {
		info.Extra = append(info.Extra,
			report.Field{Key: "backend error", Value: scrubHome(backendError)})
	}

	_, err := io.WriteString(out, report.Render(info))
	return err
}

// searchWG and searchHeadscale mirror the backend's search paths, so the report
// finds a binary the tool would find.
var (
	searchWG        = []string{"/usr/bin/wg", "/bin/wg"}
	searchHeadscale = []string{"/usr/bin/headscale", "/usr/local/bin/headscale"}
)

// versionLine turns a probe into one honest fact: the version, or that the
// binary is installed but its version could not be read, or that it is absent.
func versionLine(bin string, paths []string, result compat.Result) string {
	if result.Version != "" {
		return result.Version
	}
	if runner.Available(bin, paths...) {
		return "installed, version unknown"
	}
	return "not installed"
}

// interfacesLine renders the WireGuard interface count.
func interfacesLine(n int) string {
	if n < 0 {
		return "unknown"
	}
	return strconv.Itoa(n)
}

// presentLine renders a presence boolean.
func presentLine(present bool) string {
	if present {
		return "present"
	}
	return "absent"
}

// homePath matches a path under a home directory, the one thing a backend-build
// error could otherwise carry that names its user.
var homePath = regexp.MustCompile(`(/home|/root)(/[^\s:]*)?`)

// scrubHome replaces such a path with the kit's placeholder. A value a tool
// passes into report.Extra is its own responsibility: the kit scrubs what it
// collected, not what a tool hands it.
func scrubHome(s string) string {
	return homePath.ReplaceAllString(s, "~elsewhere~")
}

// reportUsage is the flag's one-line help, kept next to what it prints.
var reportUsage = fmt.Sprintf(
	"print the versions and machine facts a bug report needs, then exit "+
		"(no UI, no privileges, no keys or endpoints: paste it into a %s issue)",
	toolName)
