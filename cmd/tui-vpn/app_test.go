package main

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-vpn/internal/wireguard"
)

// newTestApp builds an app around the demo backend with its state already
// loaded, so a test can drive it without the tea runtime.
func newTestApp(t *testing.T) *app {
	t.Helper()
	a := newApp(wireguard.NewFake(), theme.New(), nil)
	a.width, a.height = 100, 30
	state, err := a.backend.Load(t.Context())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	a.state = state
	a.loading = false
	return a
}

func key(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// TestEveryScreenRenders checks the whole view path runs, on every tab, without
// panicking and while showing the tab's own subject.
func TestEveryScreenRenders(t *testing.T) {
	a := newTestApp(t)
	for s := wireguard.Screen(0); s < wireguard.ScreenCount; s++ {
		a.setScreen(s)
		out := a.View()
		if strings.TrimSpace(out) == "" {
			t.Fatalf("screen %d rendered nothing", s)
		}
	}
}

// TestConfirmFlowRunsExactlyThePreviewedCommand is the family's core assertion
// at the app level: pressing an action key opens a confirm dialog showing a
// command, and confirming it runs that exact command, once.
func TestConfirmFlowRunsExactlyThePreviewedCommand(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenStatus)

	// Press 'd' to take the interface down: a confirm dialog opens.
	model, _ := a.Update(key("d"))
	a = model.(*app)
	if a.mode != modeConfirm {
		t.Fatalf("pressing d did not open a confirm dialog (mode %d)", a.mode)
	}
	previewed := a.confirm.Command
	if !strings.Contains(previewed, "wg-quick down wg0") {
		t.Errorf("dialog shows %q, want the wg-quick down command", previewed)
	}

	// Confirm it: the command runs.
	model, cmd := a.Update(tea.KeyMsg{Type: tea.KeyEnter})
	a = model.(*app)
	if cmd == nil {
		t.Fatal("confirming produced no command to run")
	}
	msg := cmd()
	ran, ok := msg.(ranMsg)
	if !ok {
		t.Fatalf("expected a ranMsg, got %T", msg)
	}
	fake := a.backend.(*wireguard.Fake)
	if len(fake.Commands()) != 1 {
		t.Fatalf("ran %d commands, want exactly 1", len(fake.Commands()))
	}
	if got := a.backend.Preview(fake.Commands()[0]); got != a.backend.Preview(ran.cmd) {
		t.Errorf("the command that ran is not the one previewed")
	}
	if !strings.Contains(a.backend.Preview(fake.Commands()[0]), "wg-quick down wg0") {
		t.Errorf("ran the wrong command: %q", fake.Commands()[0])
	}
}

// TestCancellingConfirmRunsNothing is the other half: a dialog dismissed runs
// no command at all.
func TestCancellingConfirmRunsNothing(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenStatus)
	model, _ := a.Update(key("u"))
	a = model.(*app)
	if a.mode != modeConfirm {
		t.Fatal("expected a confirm dialog")
	}
	model, _ = a.Update(tea.KeyMsg{Type: tea.KeyEsc})
	a = model.(*app)
	fake := a.backend.(*wireguard.Fake)
	if len(fake.Commands()) != 0 {
		t.Errorf("cancelling still ran %d commands", len(fake.Commands()))
	}
}
