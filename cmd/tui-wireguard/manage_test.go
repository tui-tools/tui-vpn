package main

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-wireguard/internal/wireguard"
)

// confirmAndRun accepts the open confirm dialog and feeds the resulting
// command's message back into the model, the way the tea runtime would.
func confirmAndRun(t *testing.T, a *app) *app {
	t.Helper()
	if a.mode != modeConfirm {
		t.Fatalf("no confirm dialog is open (mode %d)", a.mode)
	}
	model, cmd := a.Update(tea.KeyMsg{Type: tea.KeyEnter})
	a = model.(*app)
	if cmd == nil {
		t.Fatal("confirming produced no command")
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, c := range batch {
			model, _ = a.Update(c())
			a = model.(*app)
		}
		return a
	}
	model, _ = a.Update(msg)
	return model.(*app)
}

// typeAndEnter types a line into the open input and submits it.
func typeAndEnter(t *testing.T, a *app, text string) *app {
	t.Helper()
	if a.mode != modeInput {
		t.Fatalf("no input is open (mode %d)", a.mode)
	}
	model, _ := a.Update(key(text))
	a = model.(*app)
	model, _ = a.Update(tea.KeyMsg{Type: tea.KeyEnter})
	return model.(*app)
}

// TestCreateInterfaceWizard drives the whole bootstrap through the UI: three
// inputs, three confirms, and a new interface exists in the demo state — with
// every step previewed and no private key anywhere in a dialog.
func TestCreateInterfaceWizard(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenStatus)

	model, _ := a.Update(key("N"))
	a = model.(*app)
	a = typeAndEnter(t, a, "wg9")
	a = typeAndEnter(t, a, "192.0.2.9/24")

	// The port input is prefilled with 51820; submit it as-is.
	model, _ = a.Update(tea.KeyMsg{Type: tea.KeyEnter})
	a = model.(*app)
	a = pick(t, a, roleEndpoint)

	// Step 1: keygen. The preview is a single root shell and the dialog never
	// carries a key value.
	if !strings.Contains(a.confirm.Command, "wg genkey") {
		t.Fatalf("step 1 preview = %q, want the keygen shell", a.confirm.Command)
	}
	a = confirmAndRun(t, a)

	// Step 2: write the conf. The dialog shows the whole file, which is safe
	// exactly because it contains no private key.
	if !strings.Contains(a.confirm.Command, "/etc/wireguard/wg9.conf") {
		t.Fatalf("step 2 preview = %q, want the conf install", a.confirm.Command)
	}
	if !strings.Contains(a.confirm.Body, "PostUp = wg set %i private-key /etc/wireguard/wg9.key") {
		t.Errorf("step 2 body does not show the conf:\n%s", a.confirm.Body)
	}
	if strings.Contains(a.confirm.Body, "PrivateKey") {
		t.Errorf("step 2 body inlines a private key:\n%s", a.confirm.Body)
	}
	a = confirmAndRun(t, a)

	// Step 3: the optional up.
	if !strings.Contains(a.confirm.Command, "wg-quick up wg9") {
		t.Fatalf("step 3 preview = %q, want wg-quick up", a.confirm.Command)
	}
	a = confirmAndRun(t, a)

	state, err := a.backend.Load(t.Context())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	dev, ok := state.Device("wg9")
	if !ok {
		t.Fatal("wg9 is missing after the wizard")
	}
	if !dev.Up {
		t.Error("wg9 should be up after confirming step 3")
	}
}

// TestCreateInterfaceWizardCancelStopsTheChain: cancelling the keygen confirm
// must clear the pending follow-up, so nothing later fires it by accident.
func TestCreateInterfaceWizardCancelStopsTheChain(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenStatus)
	model, _ := a.Update(key("N"))
	a = model.(*app)
	a = typeAndEnter(t, a, "wg9")
	a = typeAndEnter(t, a, "192.0.2.9/24")
	model, _ = a.Update(tea.KeyMsg{Type: tea.KeyEnter})
	a = model.(*app)
	a = pick(t, a, roleEndpoint)
	if a.after == nil {
		t.Fatal("the keygen confirm should have armed the next step")
	}
	model, _ = a.Update(tea.KeyMsg{Type: tea.KeyEsc})
	a = model.(*app)
	if a.after != nil {
		t.Error("cancelling the confirm left a chained step armed")
	}
	if got := len(a.backend.(*wireguard.Fake).Commands()); got != 0 {
		t.Errorf("cancelling still ran %d commands", got)
	}
}

// TestPeerRemovalOffersSave: after a successful peer mutation the save confirm
// opens, previewing wg-quick save and warning that it rewrites the conf.
func TestPeerRemovalOffersSave(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenPeers)
	model, _ := a.Update(key("x"))
	a = model.(*app)
	a = confirmAndRun(t, a)
	if a.mode != modeConfirm {
		t.Fatal("removing a peer did not offer to save the config")
	}
	if !strings.Contains(a.confirm.Command, "wg-quick save wg0") {
		t.Errorf("save preview = %q", a.confirm.Command)
	}
	if !strings.Contains(a.confirm.Body, "REWRITES") {
		t.Errorf("save body does not warn about the rewrite: %q", a.confirm.Body)
	}
	// Declining the save is fine: the change stays runtime-only.
	model, _ = a.Update(tea.KeyMsg{Type: tea.KeyEsc})
	a = model.(*app)
	if got := len(a.backend.(*wireguard.Fake).Commands()); got != 1 {
		t.Errorf("ran %d commands, want only the removal", got)
	}
}

// TestSaveOnDemand: "w" on the interfaces screen opens the same save confirm.
func TestSaveOnDemand(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenStatus)
	model, _ := a.Update(key("w"))
	a = model.(*app)
	if a.mode != modeConfirm || !strings.Contains(a.confirm.Command, "wg-quick save wg0") {
		t.Fatalf("w did not open the save confirm: mode %d, %q", a.mode, a.confirm.Command)
	}
}

// TestAddPeerWithPSKChainsTwoConfirms: ending the add-peer line with "psk"
// first previews the genpsk shell, then the add-peer command that passes the
// FILE PATH, never a key value.
func TestAddPeerWithPSKChainsTwoConfirms(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenPeers)
	model, _ := a.Update(key("a"))
	a = model.(*app)
	pub := "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE="
	a = typeAndEnter(t, a, pub+" 192.0.2.7/32 psk")
	if a.mode != modeConfirm || !strings.Contains(a.confirm.Command, "wg genpsk") {
		t.Fatalf("step 1 preview = %q", a.confirm.Command)
	}
	a = confirmAndRun(t, a)
	if a.mode != modeConfirm {
		t.Fatal("the add-peer confirm did not follow the genpsk")
	}
	if !strings.Contains(a.confirm.Command, "preshared-key "+wireguard.PSKPath("wg0", pub)) {
		t.Errorf("step 2 preview = %q, want the PSK file path", a.confirm.Command)
	}
	a = confirmAndRun(t, a)
	state, _ := a.backend.Load(t.Context())
	dev, _ := state.Device("wg0")
	last := dev.Peers[len(dev.Peers)-1]
	if last.PublicKey != pub || !last.HasPresharedKey {
		t.Errorf("peer not added with a PSK: %+v", last)
	}
}

// TestCreateInterfaceOnEmptyHost: the whole point of the bootstrap is that a
// host with zero interfaces can act. An empty state must still open the
// wizard.
func TestCreateInterfaceOnEmptyHost(t *testing.T) {
	a := newTestApp(t)
	a.state.Devices = nil
	a.setScreen(wireguard.ScreenStatus)
	model, _ := a.Update(key("N"))
	a = model.(*app)
	if a.mode != modeInput {
		t.Fatalf("N on an empty host did not open the wizard (mode %d): %s", a.mode, a.status)
	}
}
