package wireguard

import (
	"context"
	"testing"
)

// TestFakePreviewMatchesWhatRuns is the guarantee the whole family is built
// around: the command that ran is the command the preview showed, character for
// character, and exactly one command ran.
func TestFakePreviewMatchesWhatRuns(t *testing.T) {
	ctx := context.Background()
	f := NewFake()

	cmd, err := BuildInterfaceDown("wg0")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	preview := f.Preview(cmd)
	if preview != "wg-quick down wg0" {
		t.Errorf("preview = %q", preview)
	}
	if _, err := f.Run(ctx, cmd); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(f.Commands()) != 1 {
		t.Fatalf("ran %d commands, want 1", len(f.Commands()))
	}
	if got := f.Preview(f.Commands()[0]); got != preview {
		t.Errorf("ran %q, but the preview promised %q", got, preview)
	}
}

func TestFakeAppliesInterfaceDown(t *testing.T) {
	ctx := context.Background()
	f := NewFake()
	cmd, _ := BuildInterfaceDown("wg0")
	if _, err := f.Run(ctx, cmd); err != nil {
		t.Fatalf("run: %v", err)
	}
	state, _ := f.Load(ctx)
	dev, _ := state.Device("wg0")
	if dev.Up {
		t.Error("wg0 should be down after wg-quick down")
	}
}

func TestFakeAppliesRemovePeer(t *testing.T) {
	ctx := context.Background()
	f := NewFake()
	before, _ := f.Load(ctx)
	dev, _ := before.Device("wg0")
	target := dev.Peers[0].PublicKey

	cmd, _ := BuildRemovePeer("wg0", target)
	if _, err := f.Run(ctx, cmd); err != nil {
		t.Fatalf("run: %v", err)
	}
	after, _ := f.Load(ctx)
	dev2, _ := after.Device("wg0")
	if len(dev2.Peers) != len(dev.Peers)-1 {
		t.Errorf("peer count = %d, want one fewer", len(dev2.Peers))
	}
	for _, p := range dev2.Peers {
		if p.PublicKey == target {
			t.Error("the removed peer is still present")
		}
	}
}

func TestFakeAppliesExpireNode(t *testing.T) {
	ctx := context.Background()
	f := NewFake()
	cmd, _ := BuildExpireNode("1")
	if _, err := f.Run(ctx, cmd); err != nil {
		t.Fatalf("run: %v", err)
	}
	state, _ := f.Load(ctx)
	for _, n := range state.Headscale.Nodes {
		if n.ID == "1" && (n.Expiry.IsZero() || n.Online) {
			t.Errorf("node 1 should be expired and offline: %+v", n)
		}
	}
}

func TestFakeAppliesCreateUser(t *testing.T) {
	ctx := context.Background()
	f := NewFake()
	cmd, _ := BuildCreateUser("dana")
	if _, err := f.Run(ctx, cmd); err != nil {
		t.Fatalf("run: %v", err)
	}
	state, _ := f.Load(ctx)
	found := false
	for _, u := range state.Headscale.Users {
		if u.Name == "dana" {
			found = true
		}
	}
	if !found {
		t.Error("the new user is missing after create")
	}
}

// The demo public keys must be valid WireGuard-shaped keys, so the UI renders
// them the way real ones would.
func TestDemoKeysAreWellFormed(t *testing.T) {
	for _, k := range []string{demoIfacePub, demoPeer1Pub, demoPeer2Pub} {
		if !ValidPublicKey(k) {
			t.Errorf("demo key %q is not a valid WireGuard key", k)
		}
	}
}
