package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/runner"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-vpn/internal/wireguard"
)

// mode is the dialog currently open. It is separate from the screen, which is
// the tab the browse view shows.
type mode int

const (
	modeBrowse mode = iota
	modeConfirm
	modeInput
	modeHelp
)

// inputPurpose records what an open text input is collecting, so its result is
// turned into the right command.
type inputPurpose int

const (
	inputNone inputPurpose = iota
	inputCreateUser
	inputAddPeer
)

// app is the Bubble Tea model.
type app struct {
	backend       wireguard.Backend
	theme         theme.Theme
	backendCompat []compat.Result

	state wireguard.State

	width, height int
	screen        wireguard.Screen
	// cursor and offset are per screen, so switching tabs keeps each one's
	// position.
	cursor [wireguard.ScreenCount]int
	offset [wireguard.ScreenCount]int

	mode         mode
	confirm      ui.Confirm
	input        ui.Input
	inputPurpose inputPurpose

	status     string
	statusKind ui.StatusKind
	loading    bool
	loadFailed bool
	busy       bool
}

// loadedMsg carries the result of a read.
type loadedMsg struct {
	state wireguard.State
	err   error
}

// ranMsg carries the result of a Run.
type ranMsg struct {
	cmd    runner.Command
	output string
	err    error
}

// newApp builds the model around a backend.
func newApp(backend wireguard.Backend, th theme.Theme,
	backendCompat []compat.Result) *app {
	a := &app{backend: backend, theme: th, backendCompat: backendCompat,
		width: 80, height: 24, loading: true}
	if th.Warning != "" {
		a.setStatus(ui.StatusWarn, th.Warning)
	}
	return a
}

// Init starts the first read.
func (a *app) Init() tea.Cmd { return a.load() }

// load reads the current state in the background.
func (a *app) load() tea.Cmd {
	backend := a.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		state, err := backend.Load(ctx)
		return loadedMsg{state: state, err: err}
	}
}

// run executes a confirmed command in the background.
func (a *app) run(cmd runner.Command) tea.Cmd {
	backend := a.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		out, err := backend.Run(ctx, cmd)
		return ranMsg{cmd: cmd, output: out, err: err}
	}
}

// setStatus records a message for the status line.
func (a *app) setStatus(kind ui.StatusKind, message string) {
	a.status = message
	a.statusKind = kind
}

// setStatusf records a formatted message for the status line.
func (a *app) setStatusf(kind ui.StatusKind, format string, args ...any) {
	a.setStatus(kind, fmt.Sprintf(format, args...))
}

// Update is the main event loop.
func (a *app) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = msg.Width, msg.Height
		a.clampCursor()
		return a, nil

	case loadedMsg:
		a.loading = false
		if msg.err != nil {
			a.loadFailed = true
			a.setStatus(ui.StatusError, msg.err.Error())
			return a, nil
		}
		a.loadFailed = false
		a.state = msg.state
		a.clampCursor()
		return a, nil

	case ranMsg:
		a.busy = false
		if msg.err != nil {
			a.setStatus(ui.StatusError, runner.FirstLine(msg.err.Error()))
			return a, a.load()
		}
		summary := strings.TrimSpace(msg.output)
		if summary == "" {
			summary = "done"
		}
		a.setStatusf(ui.StatusOK, "%s: %s", msg.cmd.Description, runner.FirstLine(summary))
		a.loading = true
		return a, a.load()

	case tea.KeyMsg:
		return a.handleKey(msg)
	}

	if a.mode == modeInput {
		cmd, _ := a.input.Update(msg)
		return a, cmd
	}
	return a, nil
}

// handleKey routes a key press to the open dialog or the browse view.
func (a *app) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.Type == tea.KeyCtrlC {
		return a, tea.Quit
	}
	if a.busy {
		return a, nil
	}

	switch a.mode {
	case modeConfirm:
		return a.handleConfirm(msg)
	case modeInput:
		return a.handleInput(msg)
	case modeHelp:
		a.mode = modeBrowse
		return a, nil
	default:
		return a.handleBrowseKey(msg)
	}
}

// handleConfirm resolves the confirm dialog. This is the only path to a change.
func (a *app) handleConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	a.confirm.Update(msg)
	if !a.confirm.Done {
		return a, nil
	}
	a.mode = modeBrowse
	confirmed := a.confirm.Confirmed
	cmd, ok := a.confirm.Payload.(runner.Command)
	a.confirm = ui.Confirm{}
	if !confirmed || !ok {
		a.setStatus(ui.StatusInfo, "cancelled")
		return a, nil
	}
	a.busy = true
	a.setStatusf(ui.StatusInfo, "running %s…", a.backend.Preview(cmd))
	return a, a.run(cmd)
}

// handleInput resolves an open text input, turning its value into a command.
func (a *app) handleInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	cmd, _ := a.input.Update(msg)
	if !a.input.Done {
		return a, cmd
	}
	value := strings.TrimSpace(a.input.Value())
	accepted := a.input.Accepted
	purpose := a.inputPurpose
	a.input = ui.Input{}
	a.inputPurpose = inputNone
	a.mode = modeBrowse
	if !accepted || value == "" {
		a.setStatus(ui.StatusInfo, "cancelled")
		return a, nil
	}
	switch purpose {
	case inputCreateUser:
		return a, a.openConfirm(wireguard.BuildCreateUser(value))
	case inputAddPeer:
		return a, a.openConfirmAddPeer(value)
	}
	return a, nil
}

// handleBrowseKey handles the tabbed browse view.
func (a *app) handleBrowseKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case "q", "esc":
		return a, tea.Quit
	case "?":
		a.mode = modeHelp
		return a, nil
	case "tab", "l", "right":
		a.setScreen((a.screen + 1) % wireguard.ScreenCount)
		return a, nil
	case "shift+tab", "h", "left":
		a.setScreen((a.screen + wireguard.ScreenCount - 1) % wireguard.ScreenCount)
		return a, nil
	case "1", "2", "3", "4", "5":
		a.setScreen(wireguard.Screen(key[0] - '1'))
		return a, nil
	case "j", "down":
		a.moveCursor(1)
		return a, nil
	case "k", "up":
		a.moveCursor(-1)
		return a, nil
	case "g", "home":
		a.cursor[a.screen], a.offset[a.screen] = 0, 0
		return a, nil
	case "G", "end":
		a.cursor[a.screen] = max(a.rowCount()-1, 0)
		a.clampCursor()
		return a, nil
	case "pgdown", "ctrl+f":
		a.moveCursor(a.listHeight())
		return a, nil
	case "pgup", "ctrl+b":
		a.moveCursor(-a.listHeight())
		return a, nil
	case "r", "ctrl+r":
		a.loading = true
		return a, a.load()
	}
	return a, a.handleActionKey(key)
}

// handleActionKey dispatches the per-screen action keys.
func (a *app) handleActionKey(key string) tea.Cmd {
	switch a.screen {
	case wireguard.ScreenStatus:
		dev, ok := a.selectedDevice()
		if !ok {
			return a.warnNothing()
		}
		switch key {
		case "u":
			return a.openConfirm(wireguard.BuildInterfaceUp(dev.Name))
		case "d":
			return a.openConfirm(wireguard.BuildInterfaceDown(dev.Name))
		}
	case wireguard.ScreenPeers:
		switch key {
		case "a":
			if _, ok := a.selectedDevice(); !ok {
				return a.warnNothing()
			}
			a.input = ui.NewInput("Add peer", "PUBLIC-KEY allowed-ip[,allowed-ip]…", "")
			a.input.Help = "The peer's public key, then its allowed-ips. A private key is never accepted."
			a.inputPurpose = inputAddPeer
			a.mode = modeInput
			return nil
		case "x":
			dev, ok := a.selectedDevice()
			peer, pok := a.selectedPeer()
			if !ok || !pok {
				return a.warnNothing()
			}
			return a.openConfirm(wireguard.BuildRemovePeer(dev.Name, peer.PublicKey))
		}
	case wireguard.ScreenUsers:
		if key == "n" {
			if !a.state.Headscale.Present {
				a.setStatus(ui.StatusWarn, "no control plane")
				return nil
			}
			a.input = ui.NewInput("Create user", "name", "")
			a.input.Help = "A local Headscale user. Its identity is still owned by the IdP over OIDC."
			a.inputPurpose = inputCreateUser
			a.mode = modeInput
			return nil
		}
	case wireguard.ScreenNodes:
		if key == "e" {
			node, ok := a.selectedNode()
			if !ok {
				return a.warnNothing()
			}
			return a.openConfirm(wireguard.BuildExpireNode(node.ID))
		}
	}
	return nil
}

// warnNothing sets a status and returns no command.
func (a *app) warnNothing() tea.Cmd {
	a.setStatus(ui.StatusWarn, "nothing selected")
	return nil
}

// openConfirm builds a command and opens the confirm dialog, or reports the
// build error.
func (a *app) openConfirm(cmd runner.Command, err error) tea.Cmd {
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title:   cmd.Description,
		Body:    confirmBody(cmd),
		Command: a.backend.Preview(cmd),
		Danger:  cmd.Destructive,
		Payload: cmd,
	}
	return nil
}

// openConfirmAddPeer parses the add-peer input line and opens the confirm.
func (a *app) openConfirmAddPeer(value string) tea.Cmd {
	dev, ok := a.selectedDevice()
	if !ok {
		return a.warnNothing()
	}
	fields := strings.Fields(value)
	if len(fields) < 2 {
		a.setStatus(ui.StatusError, "give a public key and at least one allowed-ip")
		return nil
	}
	publicKey := fields[0]
	var ips []string
	for _, f := range fields[1:] {
		ips = append(ips, strings.Split(f, ",")...)
	}
	// A pre-shared key would be added by file, never on this line; phase 1
	// collects only the public key and the allowed-ips here.
	return a.openConfirm(wireguard.BuildAddPeer(dev.Name, publicKey, ips, ""))
}

// confirmBody explains an action above its command preview.
func confirmBody(cmd runner.Command) string {
	if cmd.Destructive {
		return "This changes the running configuration. Review the command below before it runs."
	}
	return "The command below will run exactly as shown."
}

// setScreen switches tab and re-clamps the cursor for the new one.
func (a *app) setScreen(s wireguard.Screen) {
	a.screen = s
	a.clampCursor()
}

// moveCursor moves the selection within the current screen.
func (a *app) moveCursor(delta int) {
	a.cursor[a.screen] += delta
	a.clampCursor()
}

// clampCursor keeps the current screen's cursor and offset in range.
func (a *app) clampCursor() {
	rows := a.rowCount()
	if rows == 0 {
		a.cursor[a.screen], a.offset[a.screen] = 0, 0
		return
	}
	a.cursor[a.screen] = min(max(a.cursor[a.screen], 0), rows-1)
	height := a.listHeight()
	if a.cursor[a.screen] < a.offset[a.screen] {
		a.offset[a.screen] = a.cursor[a.screen]
	}
	if a.cursor[a.screen] >= a.offset[a.screen]+height {
		a.offset[a.screen] = a.cursor[a.screen] - height + 1
	}
	a.offset[a.screen] = max(min(a.offset[a.screen], max(rows-height, 0)), 0)
}

// rowCount is the number of rows on the current screen.
func (a *app) rowCount() int {
	switch a.screen {
	case wireguard.ScreenStatus:
		return len(a.state.Devices)
	case wireguard.ScreenPeers:
		if dev, ok := a.selectedDevice(); ok {
			return len(dev.Peers)
		}
		return 0
	case wireguard.ScreenUsers:
		return len(a.state.Headscale.Users)
	case wireguard.ScreenNodes:
		return len(a.state.Headscale.Nodes)
	case wireguard.ScreenKeys:
		return len(a.state.Headscale.PreAuthKeys)
	}
	return 0
}

// selectedDevice is the interface highlighted on the status screen; the peers
// screen reads the same selection, so its peers are the ones on show.
func (a *app) selectedDevice() (wireguard.Device, bool) {
	i := a.cursor[wireguard.ScreenStatus]
	if i < 0 || i >= len(a.state.Devices) {
		return wireguard.Device{}, false
	}
	return a.state.Devices[i], true
}

// selectedPeer is the peer highlighted on the peers screen.
func (a *app) selectedPeer() (wireguard.Peer, bool) {
	dev, ok := a.selectedDevice()
	if !ok {
		return wireguard.Peer{}, false
	}
	i := a.cursor[wireguard.ScreenPeers]
	if i < 0 || i >= len(dev.Peers) {
		return wireguard.Peer{}, false
	}
	return dev.Peers[i], true
}

// selectedNode is the node highlighted on the nodes screen.
func (a *app) selectedNode() (wireguard.Node, bool) {
	i := a.cursor[wireguard.ScreenNodes]
	if i < 0 || i >= len(a.state.Headscale.Nodes) {
		return wireguard.Node{}, false
	}
	return a.state.Headscale.Nodes[i], true
}
