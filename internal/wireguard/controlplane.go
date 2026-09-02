package wireguard

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-kit/runner"
	"gopkg.in/yaml.v3"
)

// This file is the part of the control plane the rest of the tool could only
// infer before: Headscale's own configuration. Reading it answers the two
// questions the users screen used to shrug at — what URL do clients reach this
// server on, and which IdP does it federate identity to — and writing it is
// what turns tui-vpn from a viewer into the thing that configures OIDC.
//
// PRIVACY: the OIDC client secret is the one value in here that is a
// credential. It is typed masked, it travels to the exec site on stdin, and it
// is written to its own root-only file which config.yaml references through
// `client_secret_path`. It is therefore never in config.yaml, never in an
// argv, never in a preview, and never read back: the most this package will
// ever say about it is that one is set.

const (
	// HeadscaleConfigPath is where headscale's package looks for its
	// configuration. It is root-only on every distribution that ships it.
	HeadscaleConfigPath = "/etc/headscale/config.yaml"
	// HeadscaleConfigBackupPath is the copy taken before every write, so a
	// bad edit is one `mv` away from being undone.
	HeadscaleConfigBackupPath = HeadscaleConfigPath + ".bak"
	// OIDCClientSecretPath is the root-only file the client secret is written
	// to. config.yaml points at it instead of carrying the value.
	// The name ends in "secret" because the file it names holds one; the
	// constant is a path, which is exactly the point of the design.
	OIDCClientSecretPath = "/etc/headscale/oidc_client_secret" //nolint:gosec // a path, not a credential
	// HeadscaleService is the systemd unit a configuration change needs
	// restarted to take effect.
	HeadscaleService = "headscale"
	// DefaultOIDCScope is what an OIDC login needs at minimum to give
	// headscale a user identity it can mirror.
	DefaultOIDCScope = "openid profile email"
	// OIDCDiscoveryPath is the well-known document every OpenID Provider must
	// serve, and therefore the cheapest proof that an issuer URL is right.
	OIDCDiscoveryPath = "/.well-known/openid-configuration"
)

// ControlPlane is what /etc/headscale/config.yaml says, plus the state of the
// unit that reads it. It is read as a whole and shown as a panel: a server_url
// clients cannot reach and an issuer nobody configured are the two failures
// that make an otherwise healthy control plane useless.
type ControlPlane struct {
	// ConfigPath is the file that was read.
	ConfigPath string `json:"configPath"`
	// Readable reports that the file was read and parsed.
	Readable bool `json:"readable"`
	// Error carries why an unreadable configuration could not be read.
	Error string `json:"error,omitempty"`
	// ServerURL is the base URL clients — and the IdP's redirect — must reach.
	ServerURL string `json:"serverUrl,omitempty"`
	// ListenAddr is the address headscale binds.
	ListenAddr string `json:"listenAddr,omitempty"`
	// BaseDomain is dns.base_domain, the MagicDNS suffix. It is read only to
	// be checked against server_url: headscale refuses to start when the two
	// overlap, which is a mistake worth catching in the form rather than in a
	// failed restart.
	BaseDomain string `json:"baseDomain,omitempty"`
	// ServiceState is what `systemctl is-active headscale` answered.
	ServiceState string `json:"serviceState,omitempty"`
	// OIDC is the identity-provider section.
	OIDC OIDCConfig `json:"oidc"`
	// Raw is the file byte for byte, kept so an edit can be a minimal splice
	// of the original rather than a re-serialisation of it. It is deliberately
	// not serialised: --check prints facts, not somebody's configuration file.
	Raw string `json:"-"`
}

// OIDCConfig is the `oidc:` section of headscale's configuration.
type OIDCConfig struct {
	Issuer   string `json:"issuer,omitempty"`
	ClientID string `json:"clientId,omitempty"`
	// ClientSecretPath is the file headscale reads the secret from.
	ClientSecretPath string `json:"clientSecretPath,omitempty"`
	// ClientSecretSet reports that a secret is configured — through the file
	// or, on a configuration this tool did not write, inline. It is never the
	// secret, and there is deliberately no field that could be.
	ClientSecretSet bool `json:"clientSecretSet"`
	// ClientSecretInline reports the case worth warning about: the secret sits
	// in config.yaml itself, where every reader of that file can see it.
	ClientSecretInline bool     `json:"clientSecretInline,omitempty"`
	Scope              []string `json:"scope,omitempty"`
	AllowedDomains     []string `json:"allowedDomains,omitempty"`
	AllowedGroups      []string `json:"allowedGroups,omitempty"`
	AllowedUsers       []string `json:"allowedUsers,omitempty"`
	// OnlyStartIfAvailable is headscale's own safety switch: refuse to start
	// when the IdP cannot be reached, rather than come up letting nobody in.
	OnlyStartIfAvailable bool `json:"onlyStartIfOidcIsAvailable"`
	// PKCE reports whether the authorization-code flow is PKCE-protected.
	PKCE bool `json:"pkce"`
}

// Configured reports that the control plane actually federates identity: an
// issuer and a client id are the two values without which nothing happens.
// This is the answer the header's "oidc" fact wants — read from the
// configuration rather than guessed from who happens to have logged in.
func (o OIDCConfig) Configured() bool { return o.Issuer != "" && o.ClientID != "" }

// headscaleConfigDoc is the subset of headscale's configuration this tool
// reads. Everything else in the file is left strictly alone.
type headscaleConfigDoc struct {
	ServerURL  string `yaml:"server_url"`
	ListenAddr string `yaml:"listen_addr"`
	DNS        struct {
		BaseDomain string `yaml:"base_domain"`
	} `yaml:"dns"`
	OIDC struct {
		Issuer               string   `yaml:"issuer"`
		ClientID             string   `yaml:"client_id"`
		ClientSecret         string   `yaml:"client_secret"`
		ClientSecretPath     string   `yaml:"client_secret_path"`
		Scope                flexList `yaml:"scope"`
		AllowedDomains       flexList `yaml:"allowed_domains"`
		AllowedGroups        flexList `yaml:"allowed_groups"`
		AllowedUsers         flexList `yaml:"allowed_users"`
		OnlyStartIfAvailable *bool    `yaml:"only_start_if_oidc_is_available"`
		PKCE                 struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"pkce"`
	} `yaml:"oidc"`
}

// flexList reads a YAML value that has been seen both as a sequence and as a
// single space-separated string (scope, in particular, is written both ways in
// the wild).
type flexList []string

// UnmarshalYAML accepts a sequence or a scalar.
func (l *flexList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.SequenceNode:
		var items []string
		if err := node.Decode(&items); err != nil {
			return err
		}
		*l = items
		return nil
	case yaml.ScalarNode:
		*l = SplitList(node.Value)
		return nil
	default:
		return fmt.Errorf("expected a list or a string")
	}
}

// SplitList reads a human-typed list — commas or spaces — into its entries.
// The forms an operator types ("example.com, other.example") and the form a
// scope is written in ("openid profile email") both land here.
func SplitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// ParseHeadscaleConfig reads the parts of config.yaml this tool understands.
func ParseHeadscaleConfig(data []byte) (ControlPlane, error) {
	var doc headscaleConfigDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return ControlPlane{}, fmt.Errorf("config.yaml: %w", err)
	}
	cp := ControlPlane{
		ConfigPath: HeadscaleConfigPath,
		Readable:   true,
		ServerURL:  strings.TrimSpace(doc.ServerURL),
		ListenAddr: strings.TrimSpace(doc.ListenAddr),
		BaseDomain: strings.TrimSpace(doc.DNS.BaseDomain),
		Raw:        string(data),
	}
	o := doc.OIDC
	cp.OIDC = OIDCConfig{
		Issuer:             strings.TrimSpace(o.Issuer),
		ClientID:           strings.TrimSpace(o.ClientID),
		ClientSecretPath:   strings.TrimSpace(o.ClientSecretPath),
		ClientSecretInline: strings.TrimSpace(o.ClientSecret) != "",
		Scope:              o.Scope,
		AllowedDomains:     o.AllowedDomains,
		AllowedGroups:      o.AllowedGroups,
		AllowedUsers:       o.AllowedUsers,
		PKCE:               o.PKCE.Enabled,
		// headscale's own default is true; an absent key means the safe
		// behaviour, not the unsafe one.
		OnlyStartIfAvailable: o.OnlyStartIfAvailable == nil || *o.OnlyStartIfAvailable,
	}
	cp.OIDC.ClientSecretSet = cp.OIDC.ClientSecretPath != "" || cp.OIDC.ClientSecretInline
	return cp, nil
}

// --- validation -------------------------------------------------------------

// serverURLPattern is a plain http(s) URL with no room for anything that could
// become a second argument or break the YAML line it is written to.
var serverURLPattern = regexp.MustCompile(`^https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$`)

// ValidServerURL reports whether s is a plausible base URL.
func ValidServerURL(s string) bool {
	return s != "" && !strings.Contains(s, "\n") && serverURLPattern.MatchString(s)
}

// ServerURLWarning explains why a syntactically valid server_url will still not
// work for an OIDC login, which happens in a browser on someone else's machine:
// plain http is refused by most IdPs as a redirect target, and a loopback
// address is not reachable from anywhere but the server itself.
func ServerURLWarning(s string) string {
	switch {
	case s == "":
		return ""
	case strings.HasPrefix(s, "http://"):
		return "server_url is plain http: most IdPs refuse an http redirect URI, and clients " +
			"will send their traffic in the clear. Use https (tui-cert issues the certificate)."
	case strings.Contains(s, "127.0.0.1") || strings.Contains(s, "localhost") ||
		strings.Contains(s, "[::1]"):
		return "server_url points at loopback: a client's browser cannot reach it, so the OIDC " +
			"redirect will fail. Use the name clients actually resolve."
	}
	return ""
}

// BaseDomainConflict reports the mistake headscale itself refuses to start
// with: a server_url whose host sits inside dns.base_domain. MagicDNS owns
// every name under base_domain, so a control plane addressed by one of them
// becomes unreachable to the very clients it is serving. Catching it in the
// form is a great deal kinder than catching it in a failed restart.
func BaseDomainConflict(serverURL, baseDomain string) string {
	host := URLHost(serverURL)
	if host == "" || baseDomain == "" {
		return ""
	}
	base := strings.ToLower(strings.Trim(baseDomain, "."))
	host = strings.ToLower(host)
	if host != base && !strings.HasSuffix(host, "."+base) {
		return ""
	}
	return "server_url host " + host + " is inside dns.base_domain (" + base + "): " +
		"headscale refuses to start this way, because MagicDNS owns every name under " +
		"base_domain and clients would not be able to reach the control plane. Use a " +
		"host outside it."
}

// URLHost is the host of a URL, without the scheme, the port or any path. It
// is deliberately hand-rolled: the input has already been through
// ValidServerURL, and this only has to be right about the shapes that passes.
func URLHost(rawURL string) string {
	rest := rawURL
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		rest = rest[i+1:]
	}
	// A bracketed IPv6 literal keeps its brackets off, and its colons in.
	if strings.HasPrefix(rest, "[") {
		if end := strings.IndexByte(rest, ']'); end >= 0 {
			return rest[1:end]
		}
		return rest
	}
	if i := strings.LastIndexByte(rest, ':'); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// listenAddrPattern is a bind address: an optional host and a mandatory port.
var listenAddrPattern = regexp.MustCompile(`^[A-Za-z0-9._\[\]:-]*:[0-9]{1,5}$`)

// ValidListenAddr reports whether s is a plausible listen address.
func ValidListenAddr(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") || !listenAddrPattern.MatchString(s) {
		return false
	}
	port, err := strconv.Atoi(s[strings.LastIndexByte(s, ':')+1:])
	return err == nil && port >= 1 && port <= 65535
}

// ValidIssuerURL reports whether s is a plausible OIDC issuer URL. It is the
// same shape as a server URL: the difference is only what it points at.
func ValidIssuerURL(s string) bool { return ValidServerURL(s) }

// clientIDPattern is deliberately generous — IdPs mint client ids in every
// shape — while ruling out whitespace and the quote characters that would end
// the YAML string it is written into.
var clientIDPattern = regexp.MustCompile(`^[!-~]{1,200}$`)

// ValidClientID reports whether s is a plausible OAuth client id.
func ValidClientID(s string) bool {
	return clientIDPattern.MatchString(s) && !strings.ContainsAny(s, "\"'\\")
}

// listEntryPattern is one entry of allowed_domains, allowed_groups,
// allowed_users or scope: no whitespace, no quote, no comma.
var listEntryPattern = regexp.MustCompile(`^[!-~]{1,200}$`)

// ValidListEntry reports whether s is a plausible entry of an allow list.
func ValidListEntry(s string) bool {
	return listEntryPattern.MatchString(s) && !strings.ContainsAny(s, "\"'\\,")
}

// ValidClientSecret reports whether s can be written to the secret file. The
// only thing that matters is that it is a single non-empty line: its value is
// never parsed, never rendered and never compared.
func ValidClientSecret(s string) bool {
	return s != "" && !strings.ContainsAny(s, "\n\r")
}

// --- the minimal edit -------------------------------------------------------

// ConfigEdit is one key to set in config.yaml, addressed by its path
// ("oidc", "issuer") and carrying the value already rendered as YAML.
type ConfigEdit struct {
	Path  []string
	Value string
}

// ConfigChange is one contiguous run of lines an edit replaced, kept so the
// confirm dialog can show a diff that is provably the whole change: these are
// the only lines that differ.
type ConfigChange struct {
	// Line is the 1-based line the change starts at in the original file.
	Line int
	// Old is the lines that were there, empty for an insertion.
	Old []string
	// New is the lines that replace them.
	New []string
}

// splice is one pending edit against the source lines, half-open [start, end).
// An insertion has start == end.
type splice struct {
	start, end int
	lines      []string
}

// EditConfig applies edits to a YAML document and returns the new document
// plus the exact lines that changed.
//
// The whole point is minimality. Re-serialising a parsed document would
// reorder keys, drop blank lines and rewrite every comment in headscale's
// heavily annotated config.yaml, turning a two-line change into a thousand-line
// diff nobody can review. So the document is parsed only to LOCATE each key —
// yaml.v3's Node carries the line and column of every node — and the file
// itself is edited as lines. Everything the edits do not touch survives byte
// for byte.
func EditConfig(src string, edits []ConfigEdit) (string, []ConfigChange, error) {
	lines := strings.Split(src, "\n")

	var root *yaml.Node
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		return "", nil, fmt.Errorf("config.yaml: %w", err)
	}
	if len(doc.Content) > 0 {
		root = doc.Content[0]
	}
	if root == nil || root.Kind != yaml.MappingNode {
		return "", nil, fmt.Errorf("config.yaml: expected a mapping at the top level")
	}

	var pending []splice
	// appended collects the keys that have no home in the file at all; they
	// become one new block at the end rather than several.
	var appended []ConfigEdit

	for _, edit := range edits {
		sp, ok, err := planEdit(lines, root, edit)
		if err != nil {
			return "", nil, err
		}
		if !ok {
			appended = append(appended, edit)
			continue
		}
		if sp != nil {
			pending = append(pending, *sp)
		}
	}
	if len(appended) > 0 {
		pending = append(pending, appendBlock(lines, appended))
	}

	return applySplices(lines, pending)
}

// planEdit works out the splice one edit needs, or reports that the edit's
// parent mapping does not exist in the file.
func planEdit(lines []string, root *yaml.Node, edit ConfigEdit) (*splice, bool, error) {
	if len(edit.Path) == 0 {
		return nil, false, fmt.Errorf("an edit needs a key")
	}
	parent := root
	for i := 0; i < len(edit.Path)-1; i++ {
		value, _, ok := mapEntry(parent, edit.Path[i])
		if !ok || value.Kind != yaml.MappingNode || value.Style != 0 {
			// The section is missing, empty, or written in flow style; either
			// way there is nothing to splice into.
			return nil, false, nil
		}
		parent = value
	}

	key := edit.Path[len(edit.Path)-1]
	value, keyNode, ok := mapEntry(parent, key)
	if ok {
		indent := strings.Repeat(" ", keyNode.Column-1)
		start := keyNode.Line - 1
		end := spanEnd(lines, start, keyNode.Column-1, value)
		replacement := indent + key + ": " + edit.Value
		if len(lines) > start && lines[start] == replacement && end == start+1 {
			return nil, true, nil // already exactly this, no change
		}
		return &splice{start: start, end: end, lines: []string{replacement}}, true, nil
	}

	// The key is new but its section exists: insert it right below the
	// section's own line, at the indentation its siblings use.
	at, indent := insertPointIn(lines, parent)
	return &splice{start: at, end: at,
		lines: []string{indent + key + ": " + edit.Value}}, true, nil
}

// mapEntry finds a key in a mapping node, returning its value node and its key
// node (the key node is what carries the line and column of `key:`).
func mapEntry(node *yaml.Node, key string) (value, keyNode *yaml.Node, ok bool) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, nil, false
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1], node.Content[i], true
		}
	}
	return nil, nil, false
}

// spanEnd returns the exclusive end line of the value that starts on line
// start. A scalar on the key's own line spans one line; a block sequence or a
// nested mapping spans every following line indented deeper than the key, and
// trailing blank lines are left out so a splice never eats the separation
// between two sections.
func spanEnd(lines []string, start, keyIndent int, value *yaml.Node) int {
	end := start + 1
	if value != nil && value.Line-1 > start {
		end = value.Line - 1
	}
	for i := end; i < len(lines); i++ {
		text := lines[i]
		if strings.TrimSpace(text) == "" {
			end = i + 1
			continue
		}
		if indentOf(text) <= keyIndent {
			break
		}
		end = i + 1
	}
	// Give back the blank lines at the tail of the span: they belong to
	// whatever comes next, not to this key.
	for end > start+1 && strings.TrimSpace(lines[end-1]) == "" {
		end--
	}
	return end
}

// insertPointIn returns the line a new key should be inserted at inside a
// mapping, and the indentation to give it. Inserting directly under the
// section's first entry keeps the change to a single added line.
func insertPointIn(lines []string, parent *yaml.Node) (at int, indent string) {
	if len(parent.Content) > 0 {
		keyNode := parent.Content[0]
		return keyNode.Line - 1, strings.Repeat(" ", keyNode.Column-1)
	}
	return len(lines), ""
}

// configBlock is a section of the block appendBlock renders: its own keys,
// and the subsections below it, both in the order they were asked for.
type configBlock struct {
	name     string
	keys     []ConfigEdit
	children []*configBlock
}

// child finds or creates a subsection.
func (b *configBlock) child(name string) *configBlock {
	for _, c := range b.children {
		if c.name == name {
			return c
		}
	}
	c := &configBlock{name: name}
	b.children = append(b.children, c)
	return c
}

// render writes the block as YAML at the given depth.
func (b *configBlock) render(depth int, out *[]string) {
	indent := strings.Repeat("  ", depth)
	for _, key := range b.keys {
		*out = append(*out, indent+key.Path[len(key.Path)-1]+": "+key.Value)
	}
	for _, child := range b.children {
		*out = append(*out, indent+child.name+":")
		child.render(depth+1, out)
	}
}

// appendBlock builds the one splice that adds every key whose section is
// missing from the file, as a new block at the end of the document.
//
// It has to be a tree rather than a flat list of sections: `oidc.issuer` and
// `oidc.pkce.enabled` both arrive here when the file has no `oidc:` at all,
// and emitting a section header per key would write `oidc:` twice — a
// duplicate mapping key, which is a YAML error, not a configuration.
func appendBlock(lines []string, edits []ConfigEdit) splice {
	root := &configBlock{}
	for _, e := range edits {
		node := root
		for _, part := range e.Path[:len(e.Path)-1] {
			node = node.child(part)
		}
		node.keys = append(node.keys, e)
	}

	var out []string
	if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
		out = append(out, "")
	}
	out = append(out, "# Added by tui-vpn.")
	root.render(0, &out)
	return splice{start: len(lines), end: len(lines), lines: out}
}

// applySplices rewrites the document bottom-up, so every splice's line numbers
// still refer to the original file when it is applied.
func applySplices(lines []string, pending []splice) (string, []ConfigChange, error) {
	// Merge the insertions that land on the same line — several new keys in
	// one section all anchor there — so they come out in the order they were
	// asked for rather than reversed by the bottom-up walk.
	merged := make([]splice, 0, len(pending))
	insertAt := map[int]int{}
	for _, sp := range pending {
		if sp.start == sp.end {
			if at, seen := insertAt[sp.start]; seen {
				merged[at].lines = append(merged[at].lines, sp.lines...)
				continue
			}
			insertAt[sp.start] = len(merged)
		}
		merged = append(merged, sp)
	}

	// Bottom-up, and refuse overlapping spans rather than silently corrupting
	// the file.
	for i := 0; i < len(merged); i++ {
		for j := i + 1; j < len(merged); j++ {
			if merged[i].start < merged[j].end && merged[j].start < merged[i].end {
				return "", nil, fmt.Errorf("config.yaml: overlapping edits")
			}
		}
	}
	for i := 1; i < len(merged); i++ {
		for j := i; j > 0 && merged[j-1].start < merged[j].start; j-- {
			merged[j-1], merged[j] = merged[j], merged[j-1]
		}
	}

	var changes []ConfigChange
	out := append([]string(nil), lines...)
	for _, sp := range merged {
		old := append([]string(nil), lines[min(sp.start, len(lines)):min(sp.end, len(lines))]...)
		changes = append(changes, ConfigChange{
			Line: sp.start + 1, Old: old, New: append([]string(nil), sp.lines...),
		})
		tail := append([]string(nil), out[sp.end:]...)
		out = append(append(out[:sp.start], sp.lines...), tail...)
	}
	// The changes were collected bottom-up; a reader wants them in file order.
	for i, j := 0, len(changes)-1; i < j; i, j = i+1, j-1 {
		changes[i], changes[j] = changes[j], changes[i]
	}
	return strings.Join(out, "\n"), changes, nil
}

// indentOf is the number of leading spaces on a line.
func indentOf(s string) int {
	for i, r := range s {
		if r != ' ' {
			return i
		}
	}
	return len(s)
}

// --- rendering YAML values --------------------------------------------------

// YAMLString renders a string as a YAML scalar. It always quotes, so a value
// that happens to look like a number, a boolean or a null cannot change
// meaning on its way into the file.
func YAMLString(s string) string { return strconv.Quote(s) }

// YAMLList renders entries as a flow sequence, which keeps a list change to a
// single line and therefore to a single line of diff.
func YAMLList(items []string) string {
	if len(items) == 0 {
		return "[]"
	}
	quoted := make([]string, 0, len(items))
	for _, item := range items {
		quoted = append(quoted, strconv.Quote(item))
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// YAMLBool renders a boolean.
func YAMLBool(b bool) string { return strconv.FormatBool(b) }

// --- the settings a form collects -------------------------------------------

// ServerSettings is what the server-settings form collects.
type ServerSettings struct {
	ServerURL  string
	ListenAddr string
}

// Edits turns the server settings into the keys to set.
func (s ServerSettings) Edits() ([]ConfigEdit, error) {
	if !ValidServerURL(s.ServerURL) {
		return nil, fmt.Errorf("not a valid server_url: %q", s.ServerURL)
	}
	if !ValidListenAddr(s.ListenAddr) {
		return nil, fmt.Errorf("not a valid listen_addr: %q", s.ListenAddr)
	}
	return []ConfigEdit{
		{Path: []string{"server_url"}, Value: YAMLString(s.ServerURL)},
		{Path: []string{"listen_addr"}, Value: YAMLString(s.ListenAddr)},
	}, nil
}

// OIDCSettings is what the OIDC form collects. The client secret is not in
// here: it never joins the values that are rendered into a preview.
type OIDCSettings struct {
	Issuer         string
	ClientID       string
	Scope          []string
	AllowedDomains []string
	AllowedGroups  []string
	AllowedUsers   []string
	OnlyStart      bool
	PKCE           bool
	// ClearInlineSecret asks for the `client_secret` key already in the file
	// to be emptied, because headscale refuses to start with both a secret and
	// a secret path, and because a secret has no business being in a
	// configuration file at all.
	ClearInlineSecret bool
}

// Edits turns the OIDC settings into the keys to set. `client_secret_path` is
// always written: it is what makes the secret file the single home of the
// value.
func (o OIDCSettings) Edits() ([]ConfigEdit, error) {
	if !ValidIssuerURL(o.Issuer) {
		return nil, fmt.Errorf("not a valid issuer URL: %q", o.Issuer)
	}
	if !ValidClientID(o.ClientID) {
		return nil, fmt.Errorf("not a valid client id: %q", o.ClientID)
	}
	for _, group := range [][]string{o.Scope, o.AllowedDomains, o.AllowedGroups, o.AllowedUsers} {
		for _, entry := range group {
			if !ValidListEntry(entry) {
				return nil, fmt.Errorf("not a valid list entry: %q", entry)
			}
		}
	}
	if len(o.Scope) == 0 {
		return nil, fmt.Errorf("scope cannot be empty (try %q)", DefaultOIDCScope)
	}
	edits := []ConfigEdit{
		{Path: []string{"oidc", "issuer"}, Value: YAMLString(o.Issuer)},
		{Path: []string{"oidc", "client_id"}, Value: YAMLString(o.ClientID)},
		{Path: []string{"oidc", "client_secret_path"}, Value: YAMLString(OIDCClientSecretPath)},
		{Path: []string{"oidc", "scope"}, Value: YAMLList(o.Scope)},
		{Path: []string{"oidc", "allowed_domains"}, Value: YAMLList(o.AllowedDomains)},
		{Path: []string{"oidc", "allowed_groups"}, Value: YAMLList(o.AllowedGroups)},
		{Path: []string{"oidc", "allowed_users"}, Value: YAMLList(o.AllowedUsers)},
		{Path: []string{"oidc", "only_start_if_oidc_is_available"}, Value: YAMLBool(o.OnlyStart)},
		{Path: []string{"oidc", "pkce", "enabled"}, Value: YAMLBool(o.PKCE)},
	}
	if o.ClearInlineSecret {
		// Emptied rather than deleted: an empty value is what headscale reads
		// as "no inline secret", and deleting a line is a bigger diff than
		// blanking one.
		edits = append(edits, ConfigEdit{
			Path: []string{"oidc", "client_secret"}, Value: `""`})
	}
	return edits, nil
}

// --- commands ---------------------------------------------------------------

// BuildWriteHeadscaleConfig assembles the write of config.yaml. The content
// travels on stdin — content on an argv is one quoting bug away from being
// commands — and the shell takes a backup first, so a bad edit is one `mv`
// away from being undone. `cat >` truncates in place, which keeps the file's
// existing owner and mode: headscale may well be running as its own user.
func BuildWriteHeadscaleConfig(content string) (runner.Command, error) {
	if strings.TrimSpace(content) == "" {
		return runner.Command{}, fmt.Errorf("refusing to write an empty configuration")
	}
	script := "cp -p " + HeadscaleConfigPath + " " + HeadscaleConfigBackupPath +
		" && cat > " + HeadscaleConfigPath
	return runner.Command{
		Argv:        []string{"sh", "-c", script},
		Description: "Write " + HeadscaleConfigPath + " (backup: " + HeadscaleConfigBackupPath + ")",
		Destructive: true,
		Stdin:       content,
	}, nil
}

// BuildWriteOIDCClientSecret assembles the write of the client secret file.
//
// The secret is the Stdin of the command, which the runner deliberately keeps
// out of String and out of Preview: what the confirm dialog shows is the
// command line, and the command line here mentions only a path. `install -m
// 600` creates the file with the right mode atomically instead of
// touch-then-chmod, so there is no window in which the secret is world
// readable.
func BuildWriteOIDCClientSecret(secret string) (runner.Command, error) {
	if !ValidClientSecret(secret) {
		return runner.Command{}, fmt.Errorf("not a valid client secret")
	}
	return runner.Command{
		Argv:        []string{"install", "-m", "600", "/dev/stdin", OIDCClientSecretPath},
		Description: "Write the OIDC client secret to " + OIDCClientSecretPath,
		Stdin:       secret,
	}, nil
}

// BuildRestartHeadscale assembles the restart a configuration change needs to
// take effect. It is destructive: every node loses its control connection for
// as long as the restart takes.
func BuildRestartHeadscale() (runner.Command, error) {
	return runner.Command{
		Argv:        []string{"systemctl", "restart", HeadscaleService},
		Description: "Restart " + HeadscaleService,
		Destructive: true,
	}, nil
}

// DiscoveryURL is the well-known document for an issuer.
func DiscoveryURL(issuer string) string {
	return strings.TrimRight(issuer, "/") + OIDCDiscoveryPath
}

// BuildDiscoverIssuer assembles the read that proves an issuer URL is right:
// every OpenID Provider serves its discovery document, and it has to be
// fetched from the router itself, because the router is the machine that will
// have to reach the IdP. It changes nothing, so it runs without a confirm —
// and its failure is a warning, never a refusal to save: an IdP that is down
// this minute is not a reason to be unable to configure it.
func BuildDiscoverIssuer(issuer string) (runner.Command, error) {
	if !ValidIssuerURL(issuer) {
		return runner.Command{}, fmt.Errorf("not a valid issuer URL: %q", issuer)
	}
	return runner.Command{
		Argv:        []string{"curl", "-fsS", "--max-time", "5", DiscoveryURL(issuer)},
		Description: "Read the OIDC discovery document of " + issuer,
	}, nil
}

// DiscoveryLooksValid reports whether a discovery document is one: the
// authorization endpoint is the field a login cannot happen without.
func DiscoveryLooksValid(body string) bool {
	return strings.Contains(body, "authorization_endpoint")
}

// --- diff rendering ---------------------------------------------------------

// secretKeyPattern matches the configuration keys whose value must not be
// rendered into a diff. `client_secret_path` is a path, not a secret, and is
// deliberately excluded.
var secretKeyPattern = regexp.MustCompile(`(?i)^\s*[a-z_]*secret[a-z_]*\s*:`)

// RedactConfigLine hides the value of a line that carries a secret. A diff
// exists to be read out loud over a screen share; the one line in this file
// that could be a credential does not get to be part of that.
func RedactConfigLine(line string) string {
	if !secretKeyPattern.MatchString(line) || strings.Contains(line, "client_secret_path") {
		return line
	}
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		return line
	}
	return line[:colon+1] + " ***"
}

// RenderConfigDiff renders the changed lines, and only those, as the confirm
// dialog's body. It is minimal by construction: EditConfig reports exactly the
// runs of lines it replaced, so what is shown here is the whole change.
func RenderConfigDiff(path string, changes []ConfigChange) string {
	if len(changes) == 0 {
		return "Nothing to change: " + path + " already says this."
	}
	var b strings.Builder
	b.WriteString("--- " + path + "\n+++ " + path + " (after)\n")
	for i, change := range changes {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "@@ line %d @@\n", change.Line)
		for _, line := range change.Old {
			b.WriteString("- " + RedactConfigLine(line) + "\n")
		}
		for _, line := range change.New {
			b.WriteString("+ " + RedactConfigLine(line) + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}
