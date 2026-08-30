package wireguard

import (
	"reflect"
	"strings"
	"testing"
)

// A valid, obviously-fake public key for the builder tests.
const testPub = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="

func TestBuildInterfaceCommands(t *testing.T) {
	up, err := BuildInterfaceUp("wg0")
	if err != nil {
		t.Fatalf("up: %v", err)
	}
	if !reflect.DeepEqual(up.Argv, []string{"wg-quick", "up", "wg0"}) {
		t.Errorf("up argv = %q", up.Argv)
	}
	if up.Destructive {
		t.Error("bringing an interface up is not destructive")
	}

	down, err := BuildInterfaceDown("wg0")
	if err != nil {
		t.Fatalf("down: %v", err)
	}
	if !reflect.DeepEqual(down.Argv, []string{"wg-quick", "down", "wg0"}) {
		t.Errorf("down argv = %q", down.Argv)
	}
	if !down.Destructive {
		t.Error("taking an interface down should be marked destructive")
	}
}

func TestBuildInterfaceRejectsBadName(t *testing.T) {
	for _, bad := range []string{"", "-wg0", "wg 0", "wg0;reboot", "../etc"} {
		if _, err := BuildInterfaceUp(bad); err == nil {
			t.Errorf("accepted a bad interface name: %q", bad)
		}
	}
}

func TestBuildPeerCommands(t *testing.T) {
	rm, err := BuildRemovePeer("wg0", testPub)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !reflect.DeepEqual(rm.Argv, []string{"wg", "set", "wg0", "peer", testPub, "remove"}) {
		t.Errorf("remove argv = %q", rm.Argv)
	}

	add, err := BuildAddPeer("wg0", testPub, []string{"192.0.2.5/32", "2001:db8::5/128"}, "")
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	want := []string{"wg", "set", "wg0", "peer", testPub, "allowed-ips", "192.0.2.5/32,2001:db8::5/128"}
	if !reflect.DeepEqual(add.Argv, want) {
		t.Errorf("add argv = %q, want %q", add.Argv, want)
	}
}

func TestBuildAddPeerRejectsBadInput(t *testing.T) {
	if _, err := BuildAddPeer("wg0", "not-a-key", []string{"192.0.2.5/32"}, ""); err == nil {
		t.Error("accepted an invalid public key")
	}
	if _, err := BuildAddPeer("wg0", testPub, nil, ""); err == nil {
		t.Error("a peer with no allowed-ips should be rejected")
	}
	if _, err := BuildAddPeer("wg0", testPub, []string{"192.0.2.5/32; rm -rf"}, ""); err == nil {
		t.Error("accepted an allowed-ip that is not an address")
	}
}

// TestPresharedKeyIsAFilePathNotAValue is the family's password-shaped
// assertion: a pre-shared key reaches wg as a file it opens itself, never as a
// value on the command line, so it can never appear in the confirm dialog or in
// ps. The path is the last argument, after the "preshared-key" token.
func TestPresharedKeyIsAFilePathNotAValue(t *testing.T) {
	add, err := BuildAddPeer("wg0", testPub, []string{"192.0.2.5/32"}, "/run/tui-vpn/psk")
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	i := indexOf(add.Argv, "preshared-key")
	if i < 0 || i+1 >= len(add.Argv) {
		t.Fatalf("no preshared-key argument: %q", add.Argv)
	}
	if add.Argv[i+1] != "/run/tui-vpn/psk" {
		t.Errorf("preshared-key argument = %q, want the file path", add.Argv[i+1])
	}
}

// TestNoBuilderEmitsAPrivateKey guards the whole package's promise: no command
// builder ever names a private key, and none carries a token that even looks
// like the `private-key` flag `wg set` accepts. Adding a peer needs only its
// public key; there is no code path that puts a private key on an argv.
func TestNoBuilderEmitsAPrivateKey(t *testing.T) {
	cmds := []struct {
		name string
		make func() ([]string, error)
	}{
		{"up", func() ([]string, error) { c, e := BuildInterfaceUp("wg0"); return c.Argv, e }},
		{"down", func() ([]string, error) { c, e := BuildInterfaceDown("wg0"); return c.Argv, e }},
		{"remove", func() ([]string, error) { c, e := BuildRemovePeer("wg0", testPub); return c.Argv, e }},
		{"add", func() ([]string, error) {
			c, e := BuildAddPeer("wg0", testPub, []string{"192.0.2.5/32"}, "/run/psk")
			return c.Argv, e
		}},
		{"expire", func() ([]string, error) { c, e := BuildExpireNode("3"); return c.Argv, e }},
		{"user", func() ([]string, error) { c, e := BuildCreateUser("dana"); return c.Argv, e }},
	}
	for _, tc := range cmds {
		argv, err := tc.make()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		for _, tok := range argv {
			if strings.Contains(tok, "private-key") || strings.Contains(tok, "privatekey") {
				t.Errorf("%s command carries a private-key token: %q", tc.name, argv)
			}
		}
	}
}

func TestValidators(t *testing.T) {
	if !ValidPublicKey(testPub) {
		t.Error("a real WireGuard-shaped key should validate")
	}
	if ValidPublicKey("short") || ValidPublicKey(strings.Repeat("A", 44)) {
		t.Error("a non-key should not validate")
	}
	if !ValidInterface("wg0") || ValidInterface("-wg0") || ValidInterface("wg 0") {
		t.Error("interface validation is wrong")
	}
}

func indexOf(s []string, v string) int {
	for i, e := range s {
		if e == v {
			return i
		}
	}
	return -1
}
