package wireguard

import (
	"strings"
	"testing"
)

// TestHostProblem covers the real case behind the host check: a public IP
// typed with one digit too many was accepted as server_url, written, and the
// unit started on it.
func TestHostProblem(t *testing.T) {
	for host, ok := range map[string]bool{
		"vpn.example.com":       true,
		"localhost":             true,
		"203.0.113.10":          true,
		"0.0.0.0":               true,
		"[2001:db8::1]":         true,
		"[::]":                  true,
		"a-b.example":           true,
		"xn--bcher-kva.example": true,
		// The case from the real host, and its relatives.
		"203.0.113.1000": false,
		"203.0.1133.10":  false,
		"203.0.113":      false,
		"256.1.1.1":      false,
		"10.0.0.1.2":     false,
		// No top-level domain is numeric.
		"vpn.example.123":   false,
		"host.1":            false,
		"":                  false,
		"-bad.example":      false,
		"bad_label.example": false,
		"[2001:db8::zz]":    false,
		"[fe80::1%eth0]":    false,
		"a..example":        false,
	} {
		problem := HostProblem(host)
		if (problem == "") != ok {
			t.Errorf("HostProblem(%q) = %q, want ok=%v", host, problem, ok)
		}
	}
	if p := HostProblem("203.0.113.1000"); !strings.Contains(p, "not a valid IPv4 address") {
		t.Errorf("the reason does not name the mistyped address: %q", p)
	}
}

func TestServerURLProblem(t *testing.T) {
	for url, ok := range map[string]bool{
		"http://203.0.113.10:443":           true,
		"https://vpn.example.com":           true,
		"https://vpn.example.com/":          true,
		"https://idp.example.com/realms/x":  true,
		"https://[2001:db8::1]:8443":        true,
		"http://localhost:8080":             true,
		"http://203.0.113.1000:443":         false,
		"https://203.0.113.1000":            false,
		"https://vpn.example.com:0":         false,
		"https://vpn.example.com:99999":     false,
		"https://vpn.example.com:http":      false,
		"https://vpn.example.123/path":      false,
		"https://":                          false,
		"ftp://vpn.example.com":             false,
		"https://vpn.example.com\nrm -rf /": false,
	} {
		problem := ServerURLProblem(url)
		if (problem == "") != ok {
			t.Errorf("ServerURLProblem(%q) = %q, want ok=%v", url, problem, ok)
		}
		if ValidServerURL(url) != ok || ValidIssuerURL(url) != ok {
			t.Errorf("ValidServerURL/ValidIssuerURL(%q) disagree with ServerURLProblem", url)
		}
	}
}

func TestListenAddrProblem(t *testing.T) {
	for addr, ok := range map[string]bool{
		"0.0.0.0:443":        true,
		":8080":              true,
		"[::]:443":           true,
		"127.0.0.1:8080":     true,
		"localhost:8080":     true,
		"203.0.113.1000:443": false,
		"0.0.0.0:0":          false,
		"0.0.0.0":            false,
		"host.1:443":         false,
	} {
		if problem := ListenAddrProblem(addr); (problem == "") != ok {
			t.Errorf("ListenAddrProblem(%q) = %q, want ok=%v", addr, problem, ok)
		}
	}
}

// TestTransportRefusesAMalformedHost: the form's own check, which is what
// reopens the step with the reason.
func TestTransportRefusesAMalformedHost(t *testing.T) {
	s := TransportSettings{Transport: TransportPlainHTTP,
		ServerSettings: ServerSettings{ServerURL: "http://203.0.113.1000:443", ListenAddr: "0.0.0.0:443"}}
	err := s.CheckServerURL()
	if err == nil || !strings.Contains(err.Error(), "203.0.113.1000") {
		t.Errorf("CheckServerURL = %v, want a refusal naming the host", err)
	}
	s.ServerURL = "http://203.0.113.10:443"
	s.ListenAddr = "203.0.113.1000:443"
	if err := s.CheckListenAddr(); err == nil {
		t.Error("CheckListenAddr accepted a malformed address")
	}
}
