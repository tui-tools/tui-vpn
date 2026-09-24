package wireguard

import (
	"errors"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// This file is how clients reach the control plane: the transport headscale
// serves on, and the MagicDNS domain it hands them. Before it, `S` wrote
// server_url and listen_addr and left everything else about the transport —
// Let's Encrypt, a certificate of your own, the MagicDNS base domain — to a
// hand edit of config.yaml.
//
// There are four shapes, and they are one choice because they exclude each
// other. Writing one clears what another left behind: a Let's Encrypt
// hostname still set after switching to plain http would make headscale ask
// for a certificate nobody wanted.

// Transport is how clients reach headscale.
type Transport string

const (
	// TransportPlainHTTP is headscale serving plain http, on an IP or a name.
	// It is less alarming than it sounds: the Tailscale control protocol runs
	// over Noise, so what travels between clients and the control plane is
	// encrypted and authenticated whatever the URL scheme. The one thing that
	// needs https is a browser: an OIDC login redirects to server_url, and
	// most IdPs refuse an http redirect target.
	TransportPlainHTTP Transport = "plain-http"
	// TransportLetsEncrypt is headscale getting its own certificate from
	// Let's Encrypt through its built-in ACME client.
	TransportLetsEncrypt Transport = "letsencrypt"
	// TransportOwnCert is headscale serving a certificate and key it is given.
	TransportOwnCert Transport = "own-cert"
	// TransportReverseProxy is TLS terminated by a proxy in front, with
	// headscale bound to loopback behind it and serving no TLS itself.
	TransportReverseProxy Transport = "reverse-proxy"
)

// Transports lists the four, in the order the form offers them.
func Transports() []Transport {
	return []Transport{TransportPlainHTTP, TransportLetsEncrypt, TransportOwnCert,
		TransportReverseProxy}
}

// Label is the transport's name on screen.
func (t Transport) Label() string {
	switch t {
	case TransportLetsEncrypt:
		return "Let's Encrypt"
	case TransportOwnCert:
		return "own certificate"
	case TransportReverseProxy:
		return "reverse proxy"
	default:
		return "plain http"
	}
}

// Scheme is the server_url scheme the transport serves.
func (t Transport) Scheme() string {
	if t == TransportPlainHTTP {
		return "http"
	}
	return "https"
}

// The two ACME challenges headscale's autocert can answer.
const (
	// ChallengeTLSALPN is answered on the TLS port itself, so it is the one
	// to use when port 80 is closed.
	ChallengeTLSALPN = "TLS-ALPN-01"
	// ChallengeHTTP needs port 80 reachable from the internet
	// (tls_letsencrypt_listen, ":http" by default).
	ChallengeHTTP = "HTTP-01"
)

// DetectTransport reads which transport a configuration is set up for. A TLS
// setting decides it when there is one; without one, a loopback listen_addr
// behind an https server_url that clients can reach is a reverse proxy, and
// anything else is plain http — the stock file, which serves
// http://127.0.0.1:8080 to nobody, included.
func DetectTransport(cp ControlPlane) Transport {
	switch {
	case cp.TLSLetsEncryptHostname != "":
		return TransportLetsEncrypt
	case cp.TLSCertPath != "" || cp.TLSKeyPath != "":
		return TransportOwnCert
	case IsLoopbackHost(ListenHost(cp.ListenAddr)) && ServerURLIsHTTPS(cp.ServerURL) &&
		!IsLoopbackHost(URLHost(cp.ServerURL)):
		return TransportReverseProxy
	default:
		return TransportPlainHTTP
	}
}

// TransportNote is the panel's one-line explanation of the transport in use.
// For plain http it is the explanation the old bare warning lacked: why it is
// fine for clients, and the one case where it is not.
func TransportNote(cp ControlPlane) string {
	switch DetectTransport(cp) {
	case TransportLetsEncrypt:
		challenge := cp.TLSLetsEncryptChallenge
		if challenge == "" {
			challenge = ChallengeHTTP
		}
		return "Let's Encrypt for " + cp.TLSLetsEncryptHostname + " (" + challenge + ")"
	case TransportOwnCert:
		return "own certificate " + orNone(cp.TLSCertPath) + " · key " + orNone(cp.TLSKeyPath)
	case TransportReverseProxy:
		return "reverse proxy: TLS ends in front, headscale on " + cp.ListenAddr
	}
	if cp.OIDC.Configured() {
		return "plain http: clients are fine (the control channel is Noise-encrypted), but " +
			"the OIDC browser redirect needs https"
	}
	return "plain http: fine for clients, the control channel is Noise-encrypted; only an " +
		"OIDC browser login would need https"
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// IsIPHost reports whether a URL host is an IP literal rather than a name.
func IsIPHost(host string) bool {
	_, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil
}

// URLPort is the port of a URL, or the scheme's default when it names none.
func URLPort(rawURL string) int {
	rest := rawURL
	scheme := ""
	if i := strings.Index(rest, "://"); i >= 0 {
		scheme, rest = strings.ToLower(rest[:i]), rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		rest = rest[i+1:]
	}
	if end := strings.LastIndexByte(rest, ']'); end >= 0 {
		rest = rest[end+1:]
	}
	if i := strings.LastIndexByte(rest, ':'); i >= 0 {
		if port, err := strconv.Atoi(rest[i+1:]); err == nil && port > 0 && port < 65536 {
			return port
		}
	}
	if scheme == "https" {
		return 443
	}
	return 80
}

// dnsLabel is one label of a DNS name.
var dnsLabel = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidBaseDomain reports whether s can be dns.base_domain: what headscale's
// own documentation asks for, a fully qualified name without the trailing
// dot — at least two labels — whose last label is not all digits (an IP
// address is not a domain).
func ValidBaseDomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	_, err := strconv.Atoi(labels[len(labels)-1])
	return err != nil
}

// acmeEmailPattern is an address plain enough to be written into a YAML
// string and handed to an ACME account.
var acmeEmailPattern = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)

// ValidACMEEmail reports whether s is empty (it is optional) or an address.
func ValidACMEEmail(s string) bool { return s == "" || acmeEmailPattern.MatchString(s) }

// ValidTLSPath reports whether s is an absolute, plain path to a certificate
// or key file.
func ValidTLSPath(s string) bool { return ValidStatePath(s) && s != "/" }

// sandboxedPrefixes are the trees the packaged unit hides from the service
// (ProtectHome=, PrivateTmp=): a certificate under one of them does not exist
// as far as headscale is concerned.
var sandboxedPrefixes = []string{"/home/", "/root/", "/run/user/", "/tmp/", "/var/tmp/"}

// SandboxedPath reports whether p sits where the packaged unit cannot see.
func SandboxedPath(p string) bool {
	for _, prefix := range sandboxedPrefixes {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// AncestorsOf lists the directories a process walks through to reach p, from
// the root down, without "/" itself (which everyone can traverse).
func AncestorsOf(p string) []string {
	var dirs []string
	for dir := path.Dir(p); dir != "/" && dir != "."; dir = path.Dir(dir) {
		dirs = append([]string{dir}, dirs...)
	}
	return dirs
}

// TLSFileProblem says why the service account cannot use a certificate or
// key file, or "" when it can: it has to exist, every directory on the way to
// it has to be traversable, and the file itself readable, by that account.
// The stats are what `stat` reported for the file and its ancestors.
func TLSFileProblem(p string, stats map[string]FileStat, user, group string) string {
	st, ok := stats[p]
	if !ok {
		return p + " does not exist"
	}
	for _, dir := range AncestorsOf(p) {
		d, ok := stats[dir]
		if ok && !d.TraversableBy(user, group) {
			return dir + " (" + d.Owner() + ", mode " + strconv.FormatUint(uint64(d.Mode), 8) +
				") cannot be entered by " + user
		}
	}
	if !st.ReadableBy(user, group) {
		return p + " (" + st.Owner() + ", mode " + strconv.FormatUint(uint64(st.Mode), 8) +
			") cannot be read by " + user
	}
	return ""
}

// TraversableBy reports whether an account can enter a directory, going by
// the owner and mode alone, like ReadableBy.
func (s FileStat) TraversableBy(user, group string) bool {
	switch {
	case user == DefaultServiceUser:
		return true
	case s.User == user:
		return s.Mode&0o100 != 0
	case s.Group == group:
		return s.Mode&0o010 != 0
	default:
		return s.Mode&0o001 != 0
	}
}

// TLSStatPaths is what has to be stat'ed to judge a certificate and key: the
// two files and every directory above them.
func TLSStatPaths(paths ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		for _, q := range append(AncestorsOf(p), p) {
			if !seen[q] {
				seen[q] = true
				out = append(out, q)
			}
		}
	}
	return out
}

// TransportSettings is what the server-settings form collects.
type TransportSettings struct {
	ServerSettings
	Transport Transport
	// Challenge and ACMEEmail are Let's Encrypt's.
	Challenge string
	ACMEEmail string
	// CertPath and KeyPath are an own certificate's.
	CertPath string
	KeyPath  string
	// BaseDomain is dns.base_domain. It may be empty only when MagicDNS is
	// off: headscale refuses to start with MagicDNS on and no base domain.
	BaseDomain string
	MagicDNS   bool
}

// CheckServerURL applies the transport's rules to a server_url on its own, so
// the form can refuse it at the step it was typed rather than at the end.
func (s TransportSettings) CheckServerURL() error {
	if !ValidServerURL(s.ServerURL) {
		return fmt.Errorf("not a valid server_url: %q", s.ServerURL)
	}
	scheme := s.Transport.Scheme()
	if !strings.HasPrefix(strings.ToLower(s.ServerURL), scheme+"://") {
		if s.Transport == TransportPlainHTTP {
			return fmt.Errorf("plain http serves http://: use http://%s, or pick "+
				"Let's Encrypt or own certificate for https", hostPort(s.ServerURL))
		}
		return fmt.Errorf("%s serves https: use https://%s", s.Transport.Label(),
			hostPort(s.ServerURL))
	}
	if s.Transport == TransportLetsEncrypt {
		host := URLHost(s.ServerURL)
		if IsIPHost(host) {
			return fmt.Errorf("an IP address (%s) gets no Let's Encrypt certificate "+
				"through headscale's autocert: give the server a DNS name, or pick plain "+
				"http to reach it by IP", host)
		}
		if IsLoopbackHost(host) {
			return fmt.Errorf("%s cannot be validated by Let's Encrypt: it has to be a "+
				"public name that resolves to this server", host)
		}
	}
	return nil
}

// hostPort is the host[:port] of a URL, for a message that suggests the same
// address with another scheme.
func hostPort(rawURL string) string {
	rest := rawURL
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// CheckListenAddr applies the transport's rule to listen_addr: behind a
// reverse proxy headscale binds loopback, so nothing but the proxy reaches it.
func (s TransportSettings) CheckListenAddr() error {
	if !ValidListenAddr(s.ListenAddr) {
		return fmt.Errorf("not a valid listen_addr: %q", s.ListenAddr)
	}
	if s.Transport == TransportReverseProxy && !IsLoopbackHost(ListenHost(s.ListenAddr)) {
		return fmt.Errorf("behind a reverse proxy headscale binds loopback "+
			"(127.0.0.1:%d), so only the proxy reaches it", ListenPort(s.ListenAddr))
	}
	return nil
}

// CheckBaseDomain applies headscale's own rules to dns.base_domain: a DNS
// name, present when MagicDNS is on, and not a suffix of the server_url host
// (MagicDNS owns every name under it, so clients could not reach the control
// plane).
func (s TransportSettings) CheckBaseDomain() error {
	if s.BaseDomain == "" {
		if s.MagicDNS {
			return fmt.Errorf("dns.base_domain is required while dns.magic_dns is on " +
				"(headscale refuses to start without it)")
		}
		return nil
	}
	if !ValidBaseDomain(s.BaseDomain) {
		return fmt.Errorf("not a valid DNS name for dns.base_domain (a name with a dot, "+
			"such as tailnet.internal): %q", s.BaseDomain)
	}
	if conflict := BaseDomainConflict(s.ServerURL, s.BaseDomain); conflict != "" {
		return errors.New(conflict)
	}
	return nil
}

// Validate runs every check the form runs, for a caller that has all the
// answers at once.
func (s TransportSettings) Validate() error {
	for _, check := range []func() error{s.CheckServerURL, s.CheckListenAddr, s.CheckBaseDomain} {
		if err := check(); err != nil {
			return err
		}
	}
	switch s.Transport {
	case TransportPlainHTTP, TransportReverseProxy:
	case TransportLetsEncrypt:
		if s.Challenge != ChallengeTLSALPN && s.Challenge != ChallengeHTTP {
			return fmt.Errorf("not an ACME challenge headscale answers: %q", s.Challenge)
		}
		if !ValidACMEEmail(s.ACMEEmail) {
			return fmt.Errorf("not a valid acme_email: %q", s.ACMEEmail)
		}
	case TransportOwnCert:
		if !ValidTLSPath(s.CertPath) {
			return fmt.Errorf("not a valid tls_cert_path: %q", s.CertPath)
		}
		if !ValidTLSPath(s.KeyPath) {
			return fmt.Errorf("not a valid tls_key_path: %q", s.KeyPath)
		}
	default:
		return fmt.Errorf("not a transport: %q", s.Transport)
	}
	return nil
}

// Edits turns the settings into the keys to set, and the keys to clear.
//
// A clear is an edit that empties a key only where the file already has one:
// the lines another transport left behind are emptied, and a file that never
// had them gets no new empty lines added for the sake of it.
func (s TransportSettings) Edits() ([]ConfigEdit, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	set := func(value string, keys ...string) ConfigEdit {
		return ConfigEdit{Path: keys, Value: YAMLString(value)}
	}
	unset := func(keys ...string) ConfigEdit {
		return ConfigEdit{Path: keys, Value: `""`, ClearOnly: true}
	}
	optional := func(value string, keys ...string) ConfigEdit {
		if value == "" {
			return unset(keys...)
		}
		return set(value, keys...)
	}

	edits := []ConfigEdit{
		set(s.ServerURL, "server_url"),
		set(s.ListenAddr, "listen_addr"),
	}
	switch s.Transport {
	case TransportLetsEncrypt:
		edits = append(edits,
			optional(s.ACMEEmail, "acme_email"),
			set(URLHost(s.ServerURL), "tls_letsencrypt_hostname"),
			set(s.Challenge, "tls_letsencrypt_challenge_type"),
			unset("tls_cert_path"),
			unset("tls_key_path"))
	case TransportOwnCert:
		edits = append(edits,
			unset("tls_letsencrypt_hostname"),
			set(s.CertPath, "tls_cert_path"),
			set(s.KeyPath, "tls_key_path"))
	default:
		edits = append(edits,
			unset("tls_letsencrypt_hostname"),
			unset("tls_cert_path"),
			unset("tls_key_path"))
	}
	return append(edits, optional(s.BaseDomain, "dns", "base_domain")), nil
}
