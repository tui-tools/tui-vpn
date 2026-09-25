package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/tui-tools/tui-kit/config"
)

// tagline is the one-line description, the same words as tool.json's.
const tagline = "WireGuard interfaces and peers, from the terminal"

// legacySystemPath and legacyUserPath are the files of the old name. They are
// variables so a test can point them at a temporary directory.
var (
	legacySystemPath = config.SystemPathFor(legacyToolName)
	legacyUserPath   = config.UserPathFor(legacyToolName)
)

// loadConfig reads the configuration of this tool and, below it, the one this
// tool had as tui-vpn. The order, lowest precedence first, is:
//
//  1. the defaults;
//  2. /etc/tui-vpn/config.toml, then /etc/tui-wireguard/config.toml;
//  3. ~/.config/tui-vpn/config.toml, then ~/.config/tui-wireguard/config.toml;
//  4. TUI_WIREGUARD_* in the environment, and TUI_VPN_* for a key the new
//     prefix does not set;
//  5. the command line, applied by the caller.
//
// So a file under the new name wins over the old one at the same level, and a
// user file still wins over a machine-wide one whatever its name. Nothing is
// moved or rewritten: the tool only reads, and legacyConfigNote says which old
// file it used so the operator can rename it.
func loadConfig(opts config.Options) (config.Config, error) {
	system := orDerived(opts.SystemPath, config.SystemPathFor(toolName))
	user := orDerived(opts.UserPath, config.UserPathFor(toolName))
	cfg, err := config.LoadFrom(opts, legacySystemPath, system, legacyUserPath, user)
	if err != nil {
		return cfg, err
	}
	applyLegacyEnv(&cfg, opts)
	return cfg, nil
}

// orDerived is the override when there is one, else the derived path.
func orDerived(override, derived string) string {
	if override != "" {
		return override
	}
	return derived
}

// applyLegacyEnv reads TUI_VPN_* for each declared key whose TUI_WIREGUARD_*
// variable is not set. The kit already applied the new prefix over the files;
// the old one fills in only where the new one is silent, and like the kit it
// only ever reads declared keys.
func applyLegacyEnv(cfg *config.Config, opts config.Options) {
	if opts.EnvPrefix == "-" {
		return
	}
	prefix := orDerived(opts.EnvPrefix, config.EnvPrefixFor(toolName))
	legacy := config.EnvPrefixFor(legacyToolName)
	for key := range opts.Defaults {
		if _, ok := os.LookupEnv(envVar(prefix, key)); ok {
			continue
		}
		if value, ok := os.LookupEnv(envVar(legacy, key)); ok {
			cfg.Set(key, value)
		}
	}
}

// envVar is the variable a key is read from, the way the kit names it.
func envVar(prefix, key string) string {
	return prefix + strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
}

// legacyConfigNote says which files under the old name were read, or "" when
// none was. It is shown once in the status line at startup.
func legacyConfigNote(cfg config.Config) string {
	var old []string
	for _, src := range cfg.Sources {
		if src == expandHome(legacySystemPath) || src == expandHome(legacyUserPath) {
			old = append(old, src)
		}
	}
	if len(old) == 0 {
		return ""
	}
	return "read the old tui-vpn config " + strings.Join(old, ", ") +
		": move it under " + toolName + "/ (it is still read, below the new one)"
}

// expandHome expands a leading "~/" the way the kit does for the paths it
// records in Config.Sources.
func expandHome(path string) string {
	rest, ok := strings.CutPrefix(path, "~/")
	if !ok {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, rest)
}
