package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-vpn/internal/wireguard"
)

func TestRunCheckPrintsOneReadOfEverything(t *testing.T) {
	var out strings.Builder
	err := runCheck(context.Background(), wireguard.NewFake(),
		[]compat.Result{{Backend: backendWG, Version: "1.0.20210914"}}, &out)
	if err != nil {
		t.Fatalf("runCheck: %v", err)
	}

	var report checkReport
	if err := json.Unmarshal([]byte(out.String()), &report); err != nil {
		t.Fatalf("the output is not JSON: %v\n%s", err, out.String())
	}

	if report.Tool != toolName {
		t.Errorf("tool = %q", report.Tool)
	}
	if report.Backend != "demo" {
		t.Errorf("backend = %q, want the demo one", report.Backend)
	}
	if !report.WireGuard.Available || len(report.WireGuard.Interfaces) != 1 {
		t.Fatalf("wireguard summary is wrong: %+v", report.WireGuard)
	}
	iface := report.WireGuard.Interfaces[0]
	if iface.PeerCount != 2 || len(iface.Peers) != 2 {
		t.Errorf("interface peers = %+v, want 2", iface)
	}
	// One peer is mid-handshake (age >= 0), one has never connected (age -1).
	var never, fresh int
	for _, p := range iface.Peers {
		if p.LastHandshakeAgeSeconds < 0 {
			never++
		} else {
			fresh++
		}
	}
	if never != 1 || fresh != 1 {
		t.Errorf("handshake ages = %+v, want one fresh and one never", iface.Peers)
	}
	if !report.Headscale.Present || report.Headscale.Users != 2 || report.Headscale.Nodes != 3 {
		t.Errorf("headscale summary is wrong: %+v", report.Headscale)
	}
	if !report.Headscale.OIDCConfigured {
		t.Error("the demo control plane is OIDC-configured; --check should say so")
	}
	if report.Headscale.NodesExpired != 1 {
		t.Errorf("nodesExpired = %d, want 1 (the demo has one expired node)", report.Headscale.NodesExpired)
	}
	if report.Headscale.PreAuthKeys != 1 {
		t.Errorf("preAuthKeys = %d, want 1", report.Headscale.PreAuthKeys)
	}
	if len(report.Compat) != 1 {
		t.Errorf("compat = %+v, want the one probed backend", report.Compat)
	}
}

// TestRunCheckLeaksNoSecret is the privacy promise of --check: the JSON is
// pasted into scripts and issues, so it must carry no public key, no endpoint,
// and no address of the host it read.
func TestRunCheckLeaksNoSecret(t *testing.T) {
	var out strings.Builder
	if err := runCheck(context.Background(), wireguard.NewFake(), nil, &out); err != nil {
		t.Fatalf("runCheck: %v", err)
	}
	got := out.String()
	for _, forbidden := range []string{
		wireguard.DemoIfacePub(), wireguard.DemoPeer1Pub(), wireguard.DemoPeer2Pub(),
		"198.51.100.10", // an endpoint
		"192.0.2.2",     // a peer address
		"2001:db8::",    // a peer address
	} {
		if strings.Contains(got, forbidden) {
			t.Errorf("--check output leaks %q:\n%s", forbidden, got)
		}
	}
}

// TestCheckCarriesNoAddressOfThisHost is the promise the whole block is
// written around, enforced rather than asserted in a comment. --check is
// pasted into issues and scripts, so no URL and no address of this host may
// survive into it — the two server_url questions are booleans and the OIDC
// issuer is reduced to a host name.
func TestCheckCarriesNoAddressOfThisHost(t *testing.T) {
	var buf bytes.Buffer
	backend := wireguard.NewFake()
	if err := runCheck(t.Context(), backend, nil, &buf); err != nil {
		t.Fatalf("check: %v", err)
	}
	out := buf.String()

	// Everything the demo's configuration holds that names a machine.
	for _, forbidden := range []string{
		"https://vpn.example.com",           // server_url
		"https://idp.example.com",           // the issuer URL
		"/realms/demo",                      // the issuer's path
		"0.0.0.0:8080",                      // listen_addr
		"/etc/headscale/oidc_client_secret", // the secret path
	} {
		if strings.Contains(out, forbidden) {
			t.Errorf("--check carries %q", forbidden)
		}
	}
	// A URL scheme anywhere in the block would mean one got through.
	if strings.Contains(out, "://") {
		t.Errorf("--check carries a URL:\n%s", out)
	}

	// What replaced them still answers the questions a report needs.
	var report checkReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	cp := report.Headscale.ControlPlane
	if !cp.ServerURLSet || !cp.ServerURLHTTPS || cp.ServerURLLoopback {
		t.Errorf("the server_url booleans do not describe the demo: %+v", cp)
	}
	if cp.ListenPort != 8080 || cp.ListenLoopback {
		t.Errorf("listen port = %d, loopback = %v", cp.ListenPort, cp.ListenLoopback)
	}
	if cp.OIDCIssuer != "idp.example.com" {
		t.Errorf("oidcIssuer = %q, want the host alone", cp.OIDCIssuer)
	}
	if report.Headscale.OIDCIssuer != "idp.example.com" {
		t.Errorf("headscale.oidcIssuer = %q, want the host alone",
			report.Headscale.OIDCIssuer)
	}
}

// TestCheckReportsAnUnreachableServerURL: the booleans have to catch the two
// failures the URL was there to reveal.
func TestCheckReportsAnUnreachableServerURL(t *testing.T) {
	for _, tc := range []struct {
		url             string
		https, loopback bool
	}{
		{"https://vpn.example.com", true, false},
		{"http://vpn.example.com", false, false},
		{"https://127.0.0.1:8080", true, true},
		{"http://localhost:8080", false, true},
	} {
		if got := wireguard.ServerURLIsHTTPS(tc.url); got != tc.https {
			t.Errorf("%s: https = %v, want %v", tc.url, got, tc.https)
		}
		got := wireguard.IsLoopbackHost(wireguard.URLHost(tc.url))
		if got != tc.loopback {
			t.Errorf("%s: loopback = %v, want %v", tc.url, got, tc.loopback)
		}
	}
}
