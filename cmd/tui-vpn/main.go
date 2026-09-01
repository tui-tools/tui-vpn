// Command tui-vpn drives WireGuard and its control plane from the terminal:
// the interfaces on this host, their peers and handshakes, and — when a
// self-hosted Headscale control plane is present — the users, nodes and
// pre-authentication keys that decide who is allowed onto the network.
//
// It manages as well as reads. Every mutation — creating an interface from
// zero, bringing one up or down, adding or removing a peer, saving the runtime
// config, creating a user or a pre-auth key, expiring, renaming or deleting a
// node — is shown as the exact command line first and applied only after it is
// confirmed. There is one place a process is ever started, internal/wireguard,
// so the command the dialog showed is the command that runs.
//
// User login is deliberately not in here: identity is OpenID Connect, done in
// the client's browser against the IdP. The Headscale server exposes no web
// admin, which is the whole point of the design; this tool reads its state and
// performs the few safe mutations, nothing more.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/config"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-vpn/internal/wireguard"
)

// toolName is the binary name, which is also the configuration directory:
// /etc/tui-vpn/config.toml and ~/.config/tui-vpn/config.toml.
const toolName = "tui-vpn"

// version is stamped by the release build (-ldflags "-X main.version=…").
var version = "dev"

// defaults declares the configuration keys the tool understands. Only these are
// read from the environment (TUI_VPN_*), so an unrelated variable can never
// leak into the configuration.
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
		"run against a fake WireGuard and a fake Headscale, without reading this host")
	fs.BoolVar(&opts.check, "check", false,
		"read the interfaces and the control plane once, print the summary as JSON and exit "+
			"(no UI, nothing is changed, no keys or endpoints of this host)")
	fs.BoolVar(&opts.report, "report", false, reportUsage)
	fs.StringVar(&opts.themePath, "theme", "",
		"path to an Omarchy-style colors.toml (overrides the config file)")
	fs.StringVar(&opts.sudo, "sudo", "",
		"privilege escalation prefix, e.g. \"sudo -n\" or \"\" to disable")
	fs.BoolVar(&opts.showVersion, "version", false, "print the version and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(out, "tui-vpn — WireGuard and its control plane, from the terminal\n\n"+
			"Usage:\n  tui-vpn [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		_, _ = fmt.Fprintf(out, "\nConfiguration is read from %s, then %s, "+
			"then TUI_VPN_* in the environment.\n",
			config.SystemPathFor(toolName), config.UserPathFor(toolName))
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

	cfg, err := config.Load(config.Options{Tool: toolName, Defaults: defaults()})
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
	// with neither WireGuard nor a control plane still has to be able to file a
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

	program := tea.NewProgram(newApp(backend, theme.New(), backendCompat),
		tea.WithAltScreen())
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
