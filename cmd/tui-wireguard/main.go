// Command tui-wireguard drives WireGuard from the terminal: the interfaces on
// this host, their peers and handshakes, and the host around them (whether
// the firewall lets a handshake reach the listen port, and whether the host
// forwards for an interface).
//
// It manages as well as reads. Every mutation — creating an interface from
// zero (an endpoint, or a forwarding server with its NAT rules and listen
// port), bringing one up or down, adding or removing a peer, saving the
// runtime config — is shown as the exact command line first and applied only
// after it is confirmed. There is one place a process is ever started,
// internal/wireguard, so the command the dialog showed is the command that
// runs.
//
// This tool was called tui-vpn up to 0.4.x, when it also managed a Headscale
// control plane. That moved to tui-tailscale; the configuration it read under
// the old name is still read here (see loadConfig).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/config"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-wireguard/internal/wireguard"
)

// toolName is the binary name, which is also the configuration directory:
// /etc/tui-wireguard/config.toml and ~/.config/tui-wireguard/config.toml.
const toolName = "tui-wireguard"

// legacyToolName is the name this tool had up to 0.4.x. Its configuration
// files and its TUI_VPN_* variables are still read, below the new ones, so an
// upgrade from the tui-vpn package keeps a working configuration.
const legacyToolName = "tui-vpn"

// version is stamped by the release build (-ldflags "-X main.version=…").
var version = "dev"

// defaults declares the configuration keys the tool understands. Only these are
// read from the environment (TUI_WIREGUARD_*, and the legacy TUI_VPN_*), so an
// unrelated variable can never leak into the configuration.
func defaults() map[string]string {
	return map[string]string{
		config.KeySudo:  "sudo -n",
		config.KeyTheme: "",
	}
}

// options holds the parsed command line.
type options struct {
	demo        bool
	check       bool
	report      bool
	themePath   string
	sudo        string
	showVersion bool
	// sudoSet records whether -sudo was passed, so `--sudo ""` can disable
	// escalation instead of reading as "not given".
	sudoSet bool
}

// parseFlags defines and reads the command line.
func parseFlags(args []string, out *os.File) (options, error) {
	var opts options
	fs := flag.NewFlagSet(toolName, flag.ContinueOnError)
	fs.SetOutput(out)
	fs.BoolVar(&opts.demo, "demo", false,
		"run against a fake WireGuard host, without reading this one")
	fs.BoolVar(&opts.check, "check", false,
		"read the interfaces and the host firewall once, print the summary as JSON and exit "+
			"(no UI, nothing is changed, no keys or endpoints of this host)")
	fs.BoolVar(&opts.report, "report", false, reportUsage)
	fs.StringVar(&opts.themePath, "theme", "",
		"path to an Omarchy-style colors.toml (overrides the config file)")
	fs.StringVar(&opts.sudo, "sudo", "",
		"privilege escalation prefix, e.g. \"sudo -n\" or \"\" to disable")
	fs.BoolVar(&opts.showVersion, "version", false, "print the version and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(out, "%s — %s\n\n"+
			"Usage:\n  %s [flags]\n\nFlags:\n", toolName, tagline, toolName)
		fs.PrintDefaults()
		_, _ = fmt.Fprintf(out, "\nConfiguration is read from %s, then %s, "+
			"then %s* in the environment. The files and variables of the old name "+
			"(%s, %s, %s*) are still read, below the new ones.\n",
			config.SystemPathFor(toolName), config.UserPathFor(toolName),
			config.EnvPrefixFor(toolName), config.SystemPathFor(legacyToolName),
			config.UserPathFor(legacyToolName), config.EnvPrefixFor(legacyToolName))
	}
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "sudo" {
			opts.sudoSet = true
		}
	})
	return opts, nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, toolName+":", err)
		os.Exit(1)
	}
}

// run wires the configuration, the backend and the Bubble Tea program. Every
// tool in the family has this function, and it is worth keeping it recognisable.
func run(args []string) error {
	opts, err := parseFlags(args, os.Stdout)
	if err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if opts.showVersion {
		fmt.Println(toolName, version)
		return nil
	}

	cfg, err := loadConfig(config.Options{Tool: toolName, Defaults: defaults()})
	if err != nil {
		return err
	}
	applyOverrides(&cfg, opts)

	// The configured theme is handed to the kit through the same variable the
	// user could set by hand, so precedence stays in one place. It is set
	// before the backend is built so --report can name the theme the UI would
	// have used even on a machine where no backend can be.
	if path := cfg.Theme(); path != "" {
		if err := os.Setenv("TUI_THEME", path); err != nil {
			return err
		}
	}

	// --report is the non-interactive path that must work everywhere. It reads
	// nothing privileged and comes before the backend is required: a machine
	// with neither WireGuard nor iptables still has to be able to file a
	// usable bug report.
	if opts.report {
		return runReport(cfg, opts, os.Stdout)
	}

	// The backend versions are probed once, at startup, and shown in the
	// header. A missing binary is an empty result rather than an error.
	backendCompat := probeCompat(context.Background(), opts.demo)

	backend, err := pickBackend(cfg, opts)
	if err != nil {
		return err
	}

	// --check is the other non-interactive path: it reads once and prints, and
	// never starts a terminal program.
	if opts.check {
		return runCheck(context.Background(), backend, backendCompat, os.Stdout)
	}

	a := newApp(backend, theme.New(), backendCompat)
	if note := legacyConfigNote(cfg); note != "" && a.status == "" {
		a.setStatus(ui.StatusWarn, note)
	}
	program := tea.NewProgram(a, tea.WithAltScreen())
	_, err = program.Run()
	return err
}

// applyOverrides folds the command line into the configuration, which is the
// last and highest-precedence layer.
func applyOverrides(cfg *config.Config, opts options) {
	if opts.themePath != "" {
		cfg.Set(config.KeyTheme, opts.themePath)
	}
	// An explicitly empty -sudo disables escalation, so the flag is applied
	// whenever it was passed, empty value included.
	if opts.sudoSet {
		cfg.Set(config.KeySudo, opts.sudo)
	}
}

// pickBackend returns the demo backend or the real one.
func pickBackend(cfg config.Config, opts options) (wireguard.Backend, error) {
	if opts.demo {
		return wireguard.NewFake(), nil
	}
	return wireguard.New(cfg.SudoPrefix())
}
