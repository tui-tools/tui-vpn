package wireguard

import (
	"os"
	"strings"
	"testing"
)

// sampleConfig is shaped like the file headscale actually ships: comments, a
// blank line between sections, a nested map, and keys this tool must not
// touch. Everything asserted about minimality is asserted against it.
const sampleConfig = `# headscale configuration
---
server_url: http://127.0.0.1:8080
listen_addr: 0.0.0.0:8080

# Metrics are unrelated to anything this tool writes.
metrics_listen_addr: 127.0.0.1:9090

noise:
  private_key_path: /var/lib/headscale/noise_private.key

oidc:
  # The IdP. Empty until somebody configures it.
  only_start_if_oidc_is_available: true
  issuer: ""
  client_id: ""
  client_secret: ""
  scope:
    - openid
    - profile
  allowed_domains: []
  pkce:
    enabled: false
    method: S256

log:
  level: info
`

func TestParseHeadscaleConfig(t *testing.T) {
	cp, err := ParseHeadscaleConfig([]byte(sampleConfig))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !cp.Readable {
		t.Error("a parsed configuration must be readable")
	}
	if cp.ServerURL != "http://127.0.0.1:8080" {
		t.Errorf("server_url = %q", cp.ServerURL)
	}
	if cp.ListenAddr != "0.0.0.0:8080" {
		t.Errorf("listen_addr = %q", cp.ListenAddr)
	}
	if cp.OIDC.Configured() {
		t.Error("an empty issuer and client id is not a configured OIDC")
	}
	if cp.OIDC.ClientSecretSet {
		t.Error("an empty client_secret is not a secret that is set")
	}
	if !cp.OIDC.OnlyStartIfAvailable {
		t.Error("only_start_if_oidc_is_available: true was not read")
	}
	if got := strings.Join(cp.OIDC.Scope, " "); got != "openid profile" {
		t.Errorf("scope = %q", got)
	}
	if cp.Raw != sampleConfig {
		t.Error("Raw must be the file byte for byte, so an edit can splice it")
	}
}

// TestParseScopeAsString covers the other shape seen in the wild: a scope
// written as one space-separated string rather than a sequence.
func TestParseScopeAsString(t *testing.T) {
	cp, err := ParseHeadscaleConfig([]byte("oidc:\n  scope: openid profile email\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := strings.Join(cp.OIDC.Scope, " "); got != DefaultOIDCScope {
		t.Errorf("scope = %q, want %q", got, DefaultOIDCScope)
	}
}

// TestParseMissingOnlyStartDefaultsSafe: headscale's own default is true, so an
// absent key must not read as "start even when the IdP is down".
func TestParseMissingOnlyStartDefaultsSafe(t *testing.T) {
	cp, err := ParseHeadscaleConfig([]byte("oidc:\n  issuer: https://idp.example.com\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !cp.OIDC.OnlyStartIfAvailable {
		t.Error("an absent only_start_if_oidc_is_available must default to true")
	}
}

// TestParseInlineSecretIsFlagged: a secret in config.yaml is the case the panel
// warns about, and the flag is the only thing that ever describes it.
func TestParseInlineSecretIsFlagged(t *testing.T) {
	cp, err := ParseHeadscaleConfig([]byte("oidc:\n  client_secret: hunter2\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !cp.OIDC.ClientSecretInline || !cp.OIDC.ClientSecretSet {
		t.Error("an inline secret must be reported as set and as inline")
	}
	// The model must carry the fact, never the value.
	if strings.Contains(cp.OIDC.Issuer+cp.OIDC.ClientID+cp.OIDC.ClientSecretPath, "hunter2") {
		t.Error("the secret leaked into a rendered field")
	}
}

// TestEditConfigIsMinimal is the promise the confirm dialog rests on: an edit
// changes the lines it says it changes and nothing else. Comments, blank lines,
// key order and untouched sections all survive byte for byte.
func TestEditConfigIsMinimal(t *testing.T) {
	updated, changes, err := EditConfig(sampleConfig, []ConfigEdit{
		{Path: []string{"server_url"}, Value: YAMLString("https://vpn.example.com")},
		{Path: []string{"listen_addr"}, Value: YAMLString("127.0.0.1:8080")},
	})
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	if len(changes) != 2 {
		t.Fatalf("changes = %d, want 2: %+v", len(changes), changes)
	}

	before := strings.Split(sampleConfig, "\n")
	after := strings.Split(updated, "\n")
	if len(before) != len(after) {
		t.Fatalf("line count changed: %d → %d", len(before), len(after))
	}
	var differing []int
	for i := range before {
		if before[i] != after[i] {
			differing = append(differing, i+1)
		}
	}
	if len(differing) != 2 {
		t.Fatalf("lines that differ = %v, want exactly the two edited ones", differing)
	}
	if !strings.Contains(updated, `server_url: "https://vpn.example.com"`) {
		t.Error("the new server_url is not in the result")
	}
	// The things an operator would be furious to lose.
	for _, keep := range []string{
		"# headscale configuration",
		"# Metrics are unrelated to anything this tool writes.",
		"  private_key_path: /var/lib/headscale/noise_private.key",
		"    method: S256",
		"log:\n  level: info",
	} {
		if !strings.Contains(updated, keep) {
			t.Errorf("the edit lost %q", keep)
		}
	}
}

// TestEditConfigReplacesABlockSequence: a multi-line value is one change, not a
// half-replaced list with orphaned entries left behind.
func TestEditConfigReplacesABlockSequence(t *testing.T) {
	updated, changes, err := EditConfig(sampleConfig, []ConfigEdit{
		{Path: []string{"oidc", "scope"}, Value: YAMLList([]string{"openid", "profile", "email"})},
	})
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("changes = %d, want 1", len(changes))
	}
	if len(changes[0].Old) != 3 {
		t.Errorf("the old scope spanned %d lines, want the key and its two entries",
			len(changes[0].Old))
	}
	if strings.Contains(updated, "    - openid") {
		t.Error("an entry of the replaced sequence survived")
	}
	if !strings.Contains(updated, `  scope: ["openid", "profile", "email"]`) {
		t.Errorf("the new scope is not in the result:\n%s", updated)
	}
	// The key after the replaced block must still be there, and still indented.
	if !strings.Contains(updated, "  allowed_domains: []") {
		t.Error("the key after the replaced sequence was eaten")
	}
}

// TestEditConfigInsertsMissingKeys: keys the file does not have yet are added
// to their section rather than appended somewhere they would not be read.
func TestEditConfigInsertsMissingKeys(t *testing.T) {
	updated, _, err := EditConfig(sampleConfig, []ConfigEdit{
		{Path: []string{"oidc", "client_secret_path"}, Value: YAMLString(OIDCClientSecretPath)},
		{Path: []string{"oidc", "allowed_groups"}, Value: YAMLList([]string{"vpn"})},
	})
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	cp, err := ParseHeadscaleConfig([]byte(updated))
	if err != nil {
		t.Fatalf("the edited file no longer parses: %v", err)
	}
	if cp.OIDC.ClientSecretPath != OIDCClientSecretPath {
		t.Errorf("client_secret_path = %q", cp.OIDC.ClientSecretPath)
	}
	if strings.Join(cp.OIDC.AllowedGroups, " ") != "vpn" {
		t.Errorf("allowed_groups = %v", cp.OIDC.AllowedGroups)
	}
	// The insertion belongs to the oidc section, not to the document root.
	if !strings.Contains(updated, "  client_secret_path:") {
		t.Error("the inserted key is not indented into the oidc section")
	}
}

// TestEditConfigAppendsAMissingSection covers the host whose config.yaml has
// never heard of OIDC: the section is created rather than the edit refused.
func TestEditConfigAppendsAMissingSection(t *testing.T) {
	src := "server_url: https://vpn.example.com\nlisten_addr: 0.0.0.0:8080\n"
	updated, changes, err := EditConfig(src, []ConfigEdit{
		{Path: []string{"oidc", "issuer"}, Value: YAMLString("https://idp.example.com")},
		{Path: []string{"oidc", "client_id"}, Value: YAMLString("headscale")},
		{Path: []string{"oidc", "pkce", "enabled"}, Value: YAMLBool(true)},
	})
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	if len(changes) == 0 {
		t.Fatal("appending a section reported no change")
	}
	if !strings.HasPrefix(updated, src) {
		t.Error("appending a section rewrote what was already there")
	}
	cp, err := ParseHeadscaleConfig([]byte(updated))
	if err != nil {
		t.Fatalf("the edited file no longer parses: %v", err)
	}
	if !cp.OIDC.Configured() || !cp.OIDC.PKCE {
		t.Errorf("the appended section did not take: %+v", cp.OIDC)
	}
}

// TestEditConfigNoOpReportsNoChange: re-saving the same values must not offer
// to rewrite a file that already says exactly this.
func TestEditConfigNoOpReportsNoChange(t *testing.T) {
	src := "server_url: \"https://vpn.example.com\"\n"
	_, changes, err := EditConfig(src, []ConfigEdit{
		{Path: []string{"server_url"}, Value: YAMLString("https://vpn.example.com")},
	})
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	if len(changes) != 0 {
		t.Errorf("changes = %+v, want none", changes)
	}
}

// TestEditConfigRejectsNonMapping keeps a garbage file from being rewritten
// into a plausible-looking one.
func TestEditConfigRejectsNonMapping(t *testing.T) {
	if _, _, err := EditConfig("- a\n- b\n",
		[]ConfigEdit{{Path: []string{"server_url"}, Value: `"x"`}}); err == nil {
		t.Error("a sequence document must not be editable as a mapping")
	}
}

// TestRenderConfigDiffRedactsASecret: a diff is read out loud over a screen
// share. The one line in this file that could be a credential is not part of it.
func TestRenderConfigDiffRedactsASecret(t *testing.T) {
	updated, changes, err := EditConfig("oidc:\n  client_secret: hunter2\n",
		[]ConfigEdit{{Path: []string{"oidc", "client_secret"}, Value: `""`}})
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	diff := RenderConfigDiff(HeadscaleConfigPath, changes)
	if strings.Contains(diff, "hunter2") {
		t.Fatalf("the diff shows a secret:\n%s", diff)
	}
	if !strings.Contains(diff, "client_secret: ***") {
		t.Errorf("the redacted line is missing:\n%s", diff)
	}
	if !strings.Contains(updated, `client_secret: ""`) {
		t.Error("the inline secret was not emptied")
	}
}

// TestRenderConfigDiffKeepsTheSecretPath: the path is not the secret, and
// hiding it would hide the one thing the operator needs to check.
func TestRenderConfigDiffKeepsTheSecretPath(t *testing.T) {
	line := "  client_secret_path: /etc/headscale/oidc_client_secret"
	if got := RedactConfigLine(line); got != line {
		t.Errorf("client_secret_path was redacted: %q", got)
	}
}

func TestServerURLValidationAndWarnings(t *testing.T) {
	for _, tc := range []struct {
		url         string
		valid       bool
		wantWarning bool
	}{
		{"https://vpn.example.com", true, false},
		{"https://vpn.example.com:8443", true, false},
		{"http://vpn.example.com", true, true},
		{"https://127.0.0.1:8080", true, true},
		{"https://localhost:8080", true, true},
		{"vpn.example.com", false, false},
		{"", false, false},
		{"https://vpn.example.com\nrm -rf /", false, false},
		{"-https://vpn.example.com", false, false},
	} {
		if got := ValidServerURL(tc.url); got != tc.valid {
			t.Errorf("ValidServerURL(%q) = %v, want %v", tc.url, got, tc.valid)
		}
		if !tc.valid {
			continue
		}
		if got := ServerURLWarning(tc.url) != ""; got != tc.wantWarning {
			t.Errorf("ServerURLWarning(%q) present = %v, want %v", tc.url, got, tc.wantWarning)
		}
	}
}

func TestValidListenAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"0.0.0.0:8080":    true,
		"127.0.0.1:8080":  true,
		"[::1]:8080":      true,
		":8080":           true,
		"0.0.0.0":         false,
		"0.0.0.0:0":       false,
		"0.0.0.0:99999":   false,
		"":                false,
		"0.0.0.0:80 rm -": false,
	} {
		if got := ValidListenAddr(addr); got != want {
			t.Errorf("ValidListenAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestSplitList(t *testing.T) {
	got := SplitList(" example.com,  other.example ,, third.example ")
	if strings.Join(got, "|") != "example.com|other.example|third.example" {
		t.Errorf("SplitList = %v", got)
	}
	if len(SplitList("  ")) != 0 {
		t.Error("an empty line must split to no entries")
	}
}

// TestBuildWriteOIDCClientSecretHidesTheValue is the central privacy claim of
// the whole flow: the secret is stdin, and stdin is in neither the argv, the
// rendered command, nor the description.
func TestBuildWriteOIDCClientSecretHidesTheValue(t *testing.T) {
	// A plain, low-entropy placeholder on purpose: a test that has to write a
	// credential-shaped string should not write one that a secret scanner has
	// to decide about.
	const typed = "placeholder-value-from-the-idp"
	cmd, err := BuildWriteOIDCClientSecret(typed)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if cmd.Stdin != typed {
		t.Error("the secret must travel on stdin")
	}
	rendered := strings.Join(cmd.Argv, " ") + " " + cmd.String() + " " + cmd.Description
	if strings.Contains(rendered, typed) {
		t.Fatalf("the secret is visible in %q", rendered)
	}
	if !strings.Contains(cmd.String(), "install -m 600 /dev/stdin "+OIDCClientSecretPath) {
		t.Errorf("command = %q", cmd.String())
	}
	if _, err := BuildWriteOIDCClientSecret("two\nlines"); err == nil {
		t.Error("a multi-line secret must be refused")
	}
	if _, err := BuildWriteOIDCClientSecret(""); err == nil {
		t.Error("an empty secret must be refused")
	}
}

// TestBuildWriteHeadscaleConfigTakesABackup: the write is destructive, so it is
// marked destructive and it keeps a copy.
func TestBuildWriteHeadscaleConfigTakesABackup(t *testing.T) {
	cmd, err := BuildWriteHeadscaleConfig("server_url: https://vpn.example.com\n")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !cmd.Destructive {
		t.Error("rewriting a configuration file is destructive")
	}
	if !strings.Contains(cmd.String(), HeadscaleConfigBackupPath) {
		t.Errorf("no backup in %q", cmd.String())
	}
	if strings.Contains(cmd.String(), "server_url") {
		t.Error("the content must ride stdin, not the argv")
	}
	if _, err := BuildWriteHeadscaleConfig("  \n"); err == nil {
		t.Error("an empty configuration must be refused")
	}
}

func TestBuildDiscoverIssuer(t *testing.T) {
	cmd, err := BuildDiscoverIssuer("https://idp.example.com/realms/main/")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	want := "https://idp.example.com/realms/main" + OIDCDiscoveryPath
	if !strings.Contains(cmd.String(), want) {
		t.Errorf("command = %q, want it to read %q", cmd.String(), want)
	}
	if cmd.Destructive {
		t.Error("reading a discovery document changes nothing")
	}
	if _, err := BuildDiscoverIssuer("not a url"); err == nil {
		t.Error("a non-URL issuer must be refused")
	}
	if !DiscoveryLooksValid(`{"authorization_endpoint":"https://idp.example.com/auth"}`) {
		t.Error("a real discovery document was not recognised")
	}
	if DiscoveryLooksValid("<html>404</html>") {
		t.Error("an error page was taken for a discovery document")
	}
}

func TestOIDCSettingsEdits(t *testing.T) {
	settings := OIDCSettings{
		Issuer:         "https://idp.example.com",
		ClientID:       "headscale",
		Scope:          []string{"openid", "profile", "email"},
		AllowedDomains: []string{"example.com"},
		OnlyStart:      true,
		PKCE:           true,
	}
	edits, err := settings.Edits()
	if err != nil {
		t.Fatalf("edits: %v", err)
	}
	// client_secret_path is always written: it is what keeps the value out of
	// the configuration file.
	var hasPath bool
	for _, e := range edits {
		if e.Path[len(e.Path)-1] == "client_secret_path" {
			hasPath = true
			if !strings.Contains(e.Value, OIDCClientSecretPath) {
				t.Errorf("client_secret_path = %s", e.Value)
			}
		}
		if e.Path[len(e.Path)-1] == "client_secret" {
			t.Error("the OIDC edits must never write a client_secret value")
		}
	}
	if !hasPath {
		t.Error("client_secret_path was not written")
	}

	// The validation the form leans on.
	bad := settings
	bad.Issuer = "idp.example.com"
	if _, err := bad.Edits(); err == nil {
		t.Error("an issuer without a scheme must be refused")
	}
	bad = settings
	bad.Scope = nil
	if _, err := bad.Edits(); err == nil {
		t.Error("an empty scope must be refused")
	}
	bad = settings
	bad.AllowedDomains = []string{`ex"ample.com`}
	if _, err := bad.Edits(); err == nil {
		t.Error("a quote in a list entry must be refused")
	}
}

// TestOIDCEnabledPrefersTheConfiguration: the header's "oidc" fact stops being
// a guess as soon as there is a configuration to read.
func TestOIDCEnabledPrefersTheConfiguration(t *testing.T) {
	hs := Headscale{OIDCInferred: true}
	if !hs.OIDCEnabled() {
		t.Error("with no configuration, the inference is the answer")
	}
	hs.ControlPlane = ControlPlane{Readable: true}
	if hs.OIDCEnabled() {
		t.Error("a readable configuration with no issuer means OIDC is not configured, " +
			"whatever the inference guessed")
	}
	hs.ControlPlane.OIDC = OIDCConfig{Issuer: "https://idp.example.com", ClientID: "headscale"}
	if !hs.OIDCEnabled() {
		t.Error("a configured issuer and client id means OIDC is configured")
	}
}

// TestBaseDomainConflict guards the failure a real headscale refuses to start
// with: a server_url whose host sits inside dns.base_domain.
func TestBaseDomainConflict(t *testing.T) {
	for _, tc := range []struct {
		url, base string
		conflict  bool
	}{
		{"https://vpn.example.com", "example.com", true},
		{"https://example.com", "example.com", true},
		{"https://VPN.Example.COM:8443", "example.com", true},
		{"https://headscale.example.net", "example.com", false},
		{"https://vpn.example.com", "", false},
		{"https://notexample.com", "example.com", false},
		{"", "example.com", false},
	} {
		got := BaseDomainConflict(tc.url, tc.base) != ""
		if got != tc.conflict {
			t.Errorf("BaseDomainConflict(%q, %q) = %v, want %v",
				tc.url, tc.base, got, tc.conflict)
		}
	}
}

func TestURLHost(t *testing.T) {
	for url, want := range map[string]string{
		"https://vpn.example.com":           "vpn.example.com",
		"https://vpn.example.com:8443":      "vpn.example.com",
		"https://vpn.example.com:8443/path": "vpn.example.com",
		"http://user@vpn.example.com/x?y=1": "vpn.example.com",
		"https://[2001:db8::1]:8443":        "2001:db8::1",
		"https://127.0.0.1:8080":            "127.0.0.1",
	} {
		if got := URLHost(url); got != want {
			t.Errorf("URLHost(%q) = %q, want %q", url, got, want)
		}
	}
}

// TestParseBaseDomain reads dns.base_domain, which is the only reason the tool
// looks at the dns section at all.
func TestParseBaseDomain(t *testing.T) {
	cp, err := ParseHeadscaleConfig([]byte("dns:\n  base_domain: example.com\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cp.BaseDomain != "example.com" {
		t.Errorf("base_domain = %q", cp.BaseDomain)
	}
}

// TestEditRealHeadscaleConfig runs the editor against the configuration
// headscale actually ships — 494 lines, almost all of them comments, with the
// whole `oidc:` section commented out. That last part is the case worth having
// a real fixture for: the section has to be created, not spliced.
//
// The result of this exact edit was fed to `headscale configtest` (v0.29.3,
// from the family mirror, sha256 and attestation verified) and accepted, with
// the same values the demo uses; see testdata/README.md.
func TestEditRealHeadscaleConfig(t *testing.T) {
	src, err := os.ReadFile("testdata/headscale-config.yaml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	server, err := ServerSettings{
		ServerURL: "https://headscale.example.net", ListenAddr: "0.0.0.0:8080"}.Edits()
	if err != nil {
		t.Fatalf("server edits: %v", err)
	}
	oidc, err := OIDCSettings{
		Issuer:         "https://idp.example.net/realms/main",
		ClientID:       "headscale",
		Scope:          []string{"openid", "profile", "email"},
		AllowedDomains: []string{"example.net"},
		AllowedGroups:  []string{"vpn-users"},
		OnlyStart:      true,
		PKCE:           true,
	}.Edits()
	if err != nil {
		t.Fatalf("oidc edits: %v", err)
	}

	updated, changes, err := EditConfig(string(src), append(server, oidc...))
	if err != nil {
		t.Fatalf("edit: %v", err)
	}

	// Two in-place lines and one appended block, and nothing else.
	if len(changes) != 3 {
		t.Fatalf("changes = %d, want server_url, listen_addr and the new oidc block",
			len(changes))
	}
	before := strings.Split(string(src), "\n")
	after := strings.Split(updated, "\n")
	for i := range before {
		if i == changes[0].Line-1 || i == changes[1].Line-1 {
			continue
		}
		if i < len(after) && before[i] != after[i] {
			t.Fatalf("line %d of the shipped file changed:\n- %q\n+ %q",
				i+1, before[i], after[i])
		}
	}

	// The result is a configuration headscale can read back.
	cp, err := ParseHeadscaleConfig([]byte(updated))
	if err != nil {
		t.Fatalf("the edited file no longer parses: %v", err)
	}
	if cp.ServerURL != "https://headscale.example.net" || cp.ListenAddr != "0.0.0.0:8080" {
		t.Errorf("server settings did not take: %q %q", cp.ServerURL, cp.ListenAddr)
	}
	if !cp.OIDC.Configured() || cp.OIDC.ClientSecretPath != OIDCClientSecretPath ||
		!cp.OIDC.PKCE || !cp.OIDC.OnlyStartIfAvailable {
		t.Errorf("the appended oidc section did not take: %+v", cp.OIDC)
	}
	// The shipped file sets dns.base_domain, which is what the conflict guard
	// needs to read; and the URL above deliberately sits outside it.
	if cp.BaseDomain == "" {
		t.Error("base_domain was not read from the shipped configuration")
	}
	if BaseDomainConflict(cp.ServerURL, cp.BaseDomain) != "" {
		t.Error("this server_url should not conflict with the shipped base_domain")
	}

	// Applying the same edits again must be a no-op.
	_, again, err := EditConfig(updated, append(server, oidc...))
	if err != nil {
		t.Fatalf("second edit: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("re-applying the same settings is not idempotent: %+v", again)
	}
}
