package wireguard

import (
	"os"
	"strings"
	"testing"
)

func TestDetectTransport(t *testing.T) {
	for fixture, want := range map[string]Transport{
		"headscale-config.yaml":                 TransportPlainHTTP,
		"headscale-config-letsencrypt.yaml":     TransportLetsEncrypt,
		"headscale-config-own-cert.yaml":        TransportOwnCert,
		"headscale-config-state-elsewhere.yaml": TransportPlainHTTP,
		"headscale-config-postgres.yaml":        TransportPlainHTTP,
	} {
		if got := DetectTransport(loadFixture(t, fixture)); got != want {
			t.Errorf("%s: transport = %q, want %q", fixture, got, want)
		}
	}
	proxy := ControlPlane{ServerURL: "https://vpn.example.com", ListenAddr: "127.0.0.1:8080"}
	if got := DetectTransport(proxy); got != TransportReverseProxy {
		t.Errorf("https in front of a loopback bind = %q, want a reverse proxy", got)
	}
	cp := loadFixture(t, "headscale-config-letsencrypt.yaml")
	if cp.TLSLetsEncryptChallenge != ChallengeTLSALPN || cp.ACMEEmail != "ops@example.com" {
		t.Errorf("the Let's Encrypt settings were not read: %+v", cp)
	}
	if !loadFixture(t, "headscale-config.yaml").MagicDNS {
		t.Error("the shipped file has magic_dns on")
	}
}

func TestURLPortAndIPHost(t *testing.T) {
	for url, want := range map[string]int{
		"http://203.0.113.10:443":        443,
		"http://203.0.113.10":            80,
		"https://vpn.example.com":        443,
		"https://vpn.example.com:8443/x": 8443,
		"https://[2001:db8::1]":          443,
		"https://[2001:db8::1]:8080":     8080,
	} {
		if got := URLPort(url); got != want {
			t.Errorf("URLPort(%q) = %d, want %d", url, got, want)
		}
	}
	for host, want := range map[string]bool{
		"203.0.113.10": true, "2001:db8::1": true, "[2001:db8::1]": true,
		"vpn.example.com": false, "localhost": false,
	} {
		if got := IsIPHost(host); got != want {
			t.Errorf("IsIPHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestValidBaseDomain(t *testing.T) {
	for domain, want := range map[string]bool{
		"tailnet.internal": true, "example.com": true, "internal": false,
		"a-b.example.net": true, "Tailnet.Example.NET": true,
		"": false, "-bad.example": false, "bad-.example": false, "a..b": false,
		"example.com.": false, "203.0.113.10": false, "a b.example": false,
		"a_b.example": false, `a"b.example`: false,
		strings.Repeat("a", 64) + ".example": false,
	} {
		if got := ValidBaseDomain(domain); got != want {
			t.Errorf("ValidBaseDomain(%q) = %v, want %v", domain, got, want)
		}
	}
}

// settingsFor builds valid settings for one transport, for the tables below.
func settingsFor(transport Transport) TransportSettings {
	s := TransportSettings{
		ServerSettings: ServerSettings{ServerURL: "https://vpn.example.com",
			ListenAddr: "0.0.0.0:443"},
		Transport:  transport,
		BaseDomain: "tailnet.example.net",
		MagicDNS:   true,
	}
	switch transport {
	case TransportPlainHTTP:
		s.ServerURL = "http://203.0.113.10:443"
	case TransportLetsEncrypt:
		s.Challenge = ChallengeTLSALPN
	case TransportOwnCert:
		s.CertPath = "/etc/headscale/tls/vpn.example.com.crt"
		s.KeyPath = "/etc/headscale/tls/vpn.example.com.key"
	case TransportReverseProxy:
		s.ListenAddr = "127.0.0.1:8080"
	}
	return s
}

// TestTransportChecks is every refusal the form relies on, one case each.
func TestTransportChecks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*TransportSettings)
		want   string
	}{
		{"plain http with https", func(s *TransportSettings) {
			s.Transport, s.ServerURL = TransportPlainHTTP, "https://203.0.113.10"
		}, "use http://203.0.113.10"},
		{"https transport with http", func(s *TransportSettings) {
			s.ServerURL = "http://vpn.example.com"
		}, "serves https"},
		{"let's encrypt on an IP", func(s *TransportSettings) {
			s.Transport, s.Challenge, s.ServerURL = TransportLetsEncrypt, ChallengeHTTP,
				"https://203.0.113.10"
		}, "IP address"},
		{"let's encrypt on loopback", func(s *TransportSettings) {
			s.Transport, s.Challenge, s.ServerURL = TransportLetsEncrypt, ChallengeHTTP,
				"https://localhost"
		}, "public name"},
		{"an unknown challenge", func(s *TransportSettings) {
			s.Transport, s.Challenge = TransportLetsEncrypt, "DNS-01"
		}, "challenge"},
		{"a bad acme email", func(s *TransportSettings) {
			s.Transport, s.Challenge, s.ACMEEmail = TransportLetsEncrypt, ChallengeHTTP, "ops"
		}, "acme_email"},
		{"a relative certificate", func(s *TransportSettings) {
			s.Transport, s.CertPath, s.KeyPath = TransportOwnCert, "cert.pem", "/k.pem"
		}, "tls_cert_path"},
		{"a proxy on a public bind", func(s *TransportSettings) {
			s.Transport, s.ListenAddr = TransportReverseProxy, "0.0.0.0:8080"
		}, "loopback"},
		{"no base domain with MagicDNS", func(s *TransportSettings) {
			s.BaseDomain = ""
		}, "required"},
		{"a base domain that is not a name", func(s *TransportSettings) {
			s.BaseDomain = "not a domain"
		}, "not a valid DNS name"},
		{"server_url inside the base domain", func(s *TransportSettings) {
			s.BaseDomain = "example.com"
		}, "inside dns.base_domain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := settingsFor(TransportOwnCert)
			tc.mutate(&s)
			err := s.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate() = %v, want an error about %q", err, tc.want)
			}
		})
	}
	for _, transport := range Transports() {
		if err := settingsFor(transport).Validate(); err != nil {
			t.Errorf("%s: valid settings refused: %v", transport, err)
		}
	}
	noMagic := settingsFor(TransportPlainHTTP)
	noMagic.BaseDomain, noMagic.MagicDNS = "", false
	if err := noMagic.Validate(); err != nil {
		t.Errorf("an empty base domain with MagicDNS off was refused: %v", err)
	}
}

// editFixture applies settings to a fixture and returns the result and the
// changes.
func editFixture(t *testing.T, fixture string, s TransportSettings) (string, []ConfigChange) {
	t.Helper()
	src, err := os.ReadFile("testdata/" + fixture) //nolint:gosec // testdata is in the repository
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	edits, err := s.Edits()
	if err != nil {
		t.Fatalf("edits: %v", err)
	}
	out, changes, err := EditConfig(string(src), edits)
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	return out, changes
}

// changedLines flattens the new side of a set of changes.
func changedLines(changes []ConfigChange) []string {
	var out []string
	for _, c := range changes {
		out = append(out, c.New...)
	}
	return out
}

// TestPlainHTTPOnTheShippedConfig is the real case on the real file: three
// lines change, no TLS key is touched, and the result reads back as plain
// http with no base-domain conflict. The same edit was fed to headscale's own
// configtest; see testdata/README.md.
func TestPlainHTTPOnTheShippedConfig(t *testing.T) {
	s := settingsFor(TransportPlainHTTP)
	s.BaseDomain = "tailnet.internal"
	out, changes := editFixture(t, "headscale-config.yaml", s)
	got := strings.Join(changedLines(changes), "\n")
	want := strings.Join([]string{
		`server_url: "http://203.0.113.10:443"`,
		`listen_addr: "0.0.0.0:443"`,
		`  base_domain: "tailnet.internal"`,
	}, "\n")
	if got != want {
		t.Errorf("changes =\n%s\nwant\n%s", got, want)
	}
	cp, err := ParseHeadscaleConfig([]byte(out))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if DetectTransport(cp) != TransportPlainHTTP || cp.TLSLetsEncryptHostname != "" ||
		BaseDomainConflict(cp.ServerURL, cp.BaseDomain) != "" {
		t.Errorf("the result does not read back as plain http: %+v", cp)
	}
	// Idempotent: the same settings again change nothing.
	edits, _ := s.Edits()
	if _, again, _ := EditConfig(out, edits); len(again) != 0 {
		t.Errorf("re-applying changed %+v", again)
	}
}

// TestSwitchingTransportClearsTheOldOne: each switch empties exactly the keys
// the previous transport set, and adds no empty key where there was none.
func TestSwitchingTransportClearsTheOldOne(t *testing.T) {
	t.Run("Let's Encrypt to plain http", func(t *testing.T) {
		out, changes := editFixture(t, "headscale-config-letsencrypt.yaml",
			settingsFor(TransportPlainHTTP))
		if !contains(changedLines(changes), `tls_letsencrypt_hostname: ""`) {
			t.Errorf("the hostname was not emptied: %q", changedLines(changes))
		}
		cp, _ := ParseHeadscaleConfig([]byte(out))
		if DetectTransport(cp) != TransportPlainHTTP {
			t.Errorf("still %q after the switch", DetectTransport(cp))
		}
	})
	t.Run("own certificate to Let's Encrypt", func(t *testing.T) {
		out, changes := editFixture(t, "headscale-config-own-cert.yaml",
			settingsFor(TransportLetsEncrypt))
		lines := changedLines(changes)
		for _, want := range []string{`tls_cert_path: ""`, `tls_key_path: ""`,
			`tls_letsencrypt_hostname: "vpn.example.com"`} {
			if !contains(lines, want) {
				t.Errorf("missing %q in %q", want, lines)
			}
		}
		cp, _ := ParseHeadscaleConfig([]byte(out))
		if DetectTransport(cp) != TransportLetsEncrypt || cp.TLSLetsEncryptChallenge != ChallengeTLSALPN {
			t.Errorf("after the switch: %q %q", DetectTransport(cp), cp.TLSLetsEncryptChallenge)
		}
	})
	t.Run("a file with no TLS keys at all gains none", func(t *testing.T) {
		_, changes := editFixture(t, "headscale-config-state-elsewhere.yaml",
			settingsFor(TransportReverseProxy))
		for _, line := range changedLines(changes) {
			if strings.Contains(line, "tls_") || strings.Contains(line, "tui-vpn") {
				t.Errorf("a clear added a line: %q", line)
			}
		}
	})
}

// TestTLSFileProblem: the pair tui-cert keeps in its root-only directory is
// out of reach of a service account, and says why.
func TestTLSFileProblem(t *testing.T) {
	stats := statMap(
		stat("/etc", "root:root", 0o755),
		stat("/etc/ssl", "root:root", 0o755),
		stat("/etc/ssl/tui-cert", "root:root", 0o700),
		stat("/etc/ssl/tui-cert/vpn.crt", "root:root", 0o644),
		stat("/etc/headscale", "root:root", 0o755),
		stat("/etc/headscale/tls", "root:headscale", 0o750),
		stat("/etc/headscale/tls/vpn.crt", "root:headscale", 0o644),
		stat("/etc/headscale/tls/vpn.key", "root:headscale", 0o640),
		stat("/etc/headscale/tls/root.key", "root:root", 0o600),
	)
	for p, want := range map[string]string{
		"/etc/ssl/tui-cert/vpn.crt":   "cannot be entered",
		"/etc/headscale/tls/vpn.crt":  "",
		"/etc/headscale/tls/vpn.key":  "",
		"/etc/headscale/tls/root.key": "cannot be read",
		"/etc/headscale/tls/none.key": "does not exist",
	} {
		got := TLSFileProblem(p, stats, "headscale", "headscale")
		if (want == "") != (got == "") || !strings.Contains(got, want) {
			t.Errorf("TLSFileProblem(%s) = %q, want %q", p, got, want)
		}
	}
	if got := TLSFileProblem("/etc/ssl/tui-cert/vpn.crt", stats, "root", "root"); got != "" {
		t.Errorf("root was refused: %q", got)
	}
	if got := TLSStatPaths("/etc/a/b.crt", "/etc/a/b.key"); strings.Join(got, " ") !=
		"/etc /etc/a /etc/a/b.crt /etc/a/b.key" {
		t.Errorf("TLSStatPaths = %q", got)
	}
	if !SandboxedPath("/home/ana/cert.pem") || SandboxedPath("/etc/headscale/tls/vpn.crt") {
		t.Error("SandboxedPath is wrong")
	}
}

// TestTransportNote: plain http is explained, not only warned about.
func TestTransportNote(t *testing.T) {
	cp := loadFixture(t, "headscale-config.yaml")
	if note := TransportNote(cp); !strings.Contains(note, "Noise-encrypted") {
		t.Errorf("plain http note = %q", note)
	}
	cp.OIDC = OIDCConfig{Issuer: "https://idp.example.com", ClientID: "headscale"}
	if note := TransportNote(cp); !strings.Contains(note, "needs https") {
		t.Errorf("plain http with OIDC note = %q", note)
	}
	le := loadFixture(t, "headscale-config-letsencrypt.yaml")
	if note := TransportNote(le); !strings.Contains(note, "vpn.example.com (TLS-ALPN-01)") {
		t.Errorf("Let's Encrypt note = %q", note)
	}
}
