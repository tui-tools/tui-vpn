package wireguard

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// This file checks the host half of the addresses the control-plane forms
// write: server_url, the OIDC issuer and listen_addr.
//
// The URL patterns only check the characters, and that was not enough. A
// server_url typed with one extra digit, http://203.0.113.1000:443, passed
// them, was written, and the unit started on it: headscale does not validate
// the host either, so nothing failed on the server, and every client failed
// later on a DNS lookup for a name that looks like an IP address. A host is
// therefore either an IP literal that parses, or a DNS name whose last label
// is not all digits: no top-level domain is numeric (RFC 3696, section 2), so
// a name ending in a number can only be a mistyped address.

// HostProblem says why host cannot be the host of a URL or a bind address,
// or "" when it can. It accepts an IPv4 or IPv6 literal (with or without the
// brackets a URL puts around IPv6) and a DNS name, "localhost" included.
func HostProblem(host string) string {
	if host == "" {
		return "the host is empty"
	}
	if strings.HasPrefix(host, "[") || strings.Contains(host, ":") {
		literal := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		if addr, err := netip.ParseAddr(literal); err == nil && addr.Is6() && addr.Zone() == "" {
			return ""
		}
		return fmt.Sprintf("%s is not a valid IPv6 address", host)
	}
	if len(host) > 253 {
		return "the host name is longer than 253 characters"
	}
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	last := labels[len(labels)-1]
	if allDigits(last) {
		// A dotted-number host is an IPv4 address or nothing.
		if addr, err := netip.ParseAddr(host); err == nil && addr.Is4() {
			return ""
		}
		return fmt.Sprintf("%s is not a valid IPv4 address (four numbers from 0 to 255), "+
			"and no DNS name ends in a number", host)
	}
	for _, label := range labels {
		if !dnsLabel.MatchString(label) {
			return fmt.Sprintf("%s is not a valid host name (label %q)", host, label)
		}
	}
	return ""
}

// allDigits reports whether s is a non-empty run of ASCII digits.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// urlAuthority is the host[:port] part of a URL, with any user info dropped.
func urlAuthority(rawURL string) string {
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
	return rest
}

// ServerURLProblem says why s cannot be a server_url (or an issuer URL, which
// has the same shape), or "" when it can: an http(s) URL made of safe
// characters, whose host is an address or a name and whose port, when it
// names one, is a port.
func ServerURLProblem(s string) string {
	if s == "" || strings.ContainsAny(s, "\n\r") || !serverURLPattern.MatchString(s) {
		return fmt.Sprintf("not an http:// or https:// URL: %q", s)
	}
	authority := urlAuthority(s)
	host := URLHost(s)
	// A port is whatever follows the host; URLHost dropped it, so what is left
	// after the host has to be empty or ":<port>".
	rest := strings.TrimPrefix(authority, "["+host+"]")
	if rest == authority {
		rest = strings.TrimPrefix(authority, host)
	}
	if rest != "" {
		port, err := strconv.Atoi(strings.TrimPrefix(rest, ":"))
		if !strings.HasPrefix(rest, ":") || err != nil || port < 1 || port > 65535 {
			return fmt.Sprintf("%q does not end in a valid port", authority)
		}
	}
	if strings.HasPrefix(authority, "[") {
		host = "[" + host + "]"
	}
	return HostProblem(host)
}

// ListenAddrProblem says why s cannot be listen_addr, or "" when it can: an
// optional host that is an address or a name, and a port.
func ListenAddrProblem(s string) string {
	if s == "" || strings.HasPrefix(s, "-") || !listenAddrPattern.MatchString(s) {
		return fmt.Sprintf("not a host:port bind address: %q", s)
	}
	i := strings.LastIndexByte(s, ':')
	port, err := strconv.Atoi(s[i+1:])
	if err != nil || port < 1 || port > 65535 {
		return fmt.Sprintf("not a port from 1 to 65535: %q", s[i+1:])
	}
	host := s[:i]
	if host == "" {
		return "" // ":8080" binds every interface
	}
	return HostProblem(host)
}
