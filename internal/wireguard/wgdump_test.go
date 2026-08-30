package wireguard

import (
	"os"
	"path/filepath"
	"testing"
)

func readFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // testdata is in the repository
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

func TestParseWgDump(t *testing.T) {
	devices := ParseWgDump(readFixture(t, "wg-show-all-dump.txt"))
	if len(devices) != 2 {
		t.Fatalf("got %d devices, want 2", len(devices))
	}

	wg0 := devices[0]
	if wg0.Name != "wg0" {
		t.Errorf("first device = %q, want wg0", wg0.Name)
	}
	if wg0.HasPrivateKey {
		t.Error("the fixture's wg0 has (none) for its private key")
	}
	if wg0.ListenPort != 51820 {
		t.Errorf("listen port = %d, want 51820", wg0.ListenPort)
	}
	if len(wg0.Peers) != 2 {
		t.Fatalf("wg0 has %d peers, want 2", len(wg0.Peers))
	}

	// The mid-handshake peer: an endpoint, a handshake, a pre-shared key, and
	// non-zero counters.
	p0 := wg0.Peers[0]
	if p0.Endpoint != "198.51.100.10:51820" {
		t.Errorf("peer endpoint = %q", p0.Endpoint)
	}
	if !p0.HasPresharedKey {
		t.Error("peer 0 has a pre-shared key in the fixture")
	}
	if p0.LastHandshake.IsZero() {
		t.Error("peer 0 has a handshake time")
	}
	if p0.RxBytes != 8452112 || p0.TxBytes != 3221004 {
		t.Errorf("peer 0 transfer = %d/%d", p0.RxBytes, p0.TxBytes)
	}
	if p0.Keepalive != 25 {
		t.Errorf("peer 0 keepalive = %d, want 25", p0.Keepalive)
	}

	// The never-connected peer: no endpoint, no handshake, two allowed-ips.
	p1 := wg0.Peers[1]
	if p1.Endpoint != "" || !p1.LastHandshake.IsZero() {
		t.Errorf("peer 1 should be never-connected: %+v", p1)
	}
	if len(p1.AllowedIPs) != 2 {
		t.Errorf("peer 1 allowed-ips = %v, want two", p1.AllowedIPs)
	}
}

func TestParseWgDumpEmpty(t *testing.T) {
	if got := ParseWgDump(""); len(got) != 0 {
		t.Errorf("empty dump = %v, want none", got)
	}
	// A line with the wrong field count is skipped, not fatal.
	if got := ParseWgDump("garbage line with spaces\n\t\t\t\n"); len(got) != 0 {
		t.Errorf("junk dump = %v, want none", got)
	}
}
