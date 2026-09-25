package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tui-tools/tui-kit/config"
)

// legacyFixture points the four configuration files at a temporary directory,
// writes the ones given, and returns the options to load them with.
func legacyFixture(t *testing.T, files map[string]string) config.Options {
	t.Helper()
	dir := t.TempDir()
	path := func(name string) string { return filepath.Join(dir, name, "config.toml") }
	for name, body := range files {
		if err := os.MkdirAll(filepath.Dir(path(name)), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path(name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldSystem, oldUser := legacySystemPath, legacyUserPath
	legacySystemPath, legacyUserPath = path("etc-tui-vpn"), path("home-tui-vpn")
	t.Cleanup(func() { legacySystemPath, legacyUserPath = oldSystem, oldUser })
	for _, v := range []string{"TUI_WIREGUARD_SUDO", "TUI_VPN_SUDO"} {
		if value, ok := os.LookupEnv(v); ok {
			t.Cleanup(func() { _ = os.Setenv(v, value) })
			_ = os.Unsetenv(v)
		}
	}
	return config.Options{Tool: toolName, Defaults: defaults(),
		SystemPath: path("etc-tui-wireguard"), UserPath: path("home-tui-wireguard")}
}

// An upgrade from tui-vpn keeps its configuration: the old file is read, and
// the tool says which one so it can be moved.
func TestLegacyConfigIsRead(t *testing.T) {
	opts := legacyFixture(t, map[string]string{"etc-tui-vpn": `sudo = "doas"` + "\n"})
	cfg, err := loadConfig(opts)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got := cfg.String(config.KeySudo, ""); got != "doas" {
		t.Errorf("sudo = %q, want the legacy file's doas", got)
	}
	note := legacyConfigNote(cfg)
	if !strings.Contains(note, "tui-vpn") || !strings.Contains(note, toolName) {
		t.Errorf("the note does not name the old file and the new place: %q", note)
	}
}

// At the same level the new name wins; a user file wins over a machine-wide
// one whatever its name.
func TestNewConfigWinsOverLegacy(t *testing.T) {
	opts := legacyFixture(t, map[string]string{
		"etc-tui-vpn":        `sudo = "doas"` + "\n",
		"etc-tui-wireguard":  `sudo = "sudo -n"` + "\n",
		"home-tui-vpn":       `theme = "/legacy/colors.toml"` + "\n",
		"home-tui-wireguard": "",
	})
	cfg, err := loadConfig(opts)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got := cfg.String(config.KeySudo, ""); got != "sudo -n" {
		t.Errorf("sudo = %q, want the new system file's", got)
	}
	if got := cfg.Theme(); got != "/legacy/colors.toml" {
		t.Errorf("theme = %q, want the legacy user file's (user beats system)", got)
	}
}

// With no file of the old name there is nothing to say.
func TestNoLegacyNoteWithoutLegacyFiles(t *testing.T) {
	opts := legacyFixture(t, map[string]string{"etc-tui-wireguard": `sudo = ""` + "\n"})
	cfg, err := loadConfig(opts)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if note := legacyConfigNote(cfg); note != "" {
		t.Errorf("note = %q, want none", note)
	}
}

// TUI_VPN_* fills in a key TUI_WIREGUARD_* does not set, and loses to it when
// both are set.
func TestLegacyEnvironment(t *testing.T) {
	opts := legacyFixture(t, nil)
	t.Setenv("TUI_VPN_SUDO", "doas")
	cfg, err := loadConfig(opts)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got := cfg.String(config.KeySudo, ""); got != "doas" {
		t.Errorf("sudo = %q, want TUI_VPN_SUDO's", got)
	}
	t.Setenv("TUI_WIREGUARD_SUDO", "sudo -n")
	cfg, err = loadConfig(opts)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got := cfg.String(config.KeySudo, ""); got != "sudo -n" {
		t.Errorf("sudo = %q, want TUI_WIREGUARD_SUDO's", got)
	}
}
