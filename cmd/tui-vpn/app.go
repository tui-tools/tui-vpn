package main

import (
	"context"
	"fmt"
	"strconv"
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
	// The create-interface wizard is three inputs in a row.
	inputNewIfaceName
	inputNewIfaceAddress
	inputNewIfacePort
	inputCreatePreAuthKey
	inputRenameNode
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

	// draft collects the create-interface wizard's answers across its inputs.
	draft struct{ name, address, port string }
	// after, when set, runs once on the next successful command result. It is
	// how multi-step flows chain: keygen → write conf → offer up, and
	// genpsk → add peer. Cancelling a confirm clears it.
	after func(output string) tea.Cmd

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
			a.after = nil
			a.setStatus(ui.StatusError, runner.FirstLine(msg.err.Error()))
			return a, a.load()
		}

		// A chained flow (create interface, add peer with PSK) takes over the
		// next step; the reload still happens underneath it.
		if next := a.after; next != nil {
			a.after = nil
			a.loading = true
			if cmd := next(msg.output); cmd != nil {
				return a, tea.Batch(cmd, a.load())
			}
			return a, a.load()
		}

		// A created pre-auth key is printed by headscale exactly once, and
		// shown here exactly once. It is never stored: the list keeps only
		// the prefix, like headscale's own list does.
		if isPreAuthCreate(msg.cmd) {
			a.setStatusf(ui.StatusWarn, "pre-auth key (shown once — copy it now): %s",
				lastLine(msg.output))
			a.loading = true
			return a, a.load()
		}

		summary := strings.TrimSpace(msg.output)
		if summary == "" {
			summary = "done"
		}
		a.setStatusf(ui.StatusOK, "%s: %s", msg.cmd.Description, runner.FirstLine(summary))
		a.loading = true

		// A peer change is runtime-only until it is saved: offer the save
		// right away, cancellable like any other confirm.
		if iface, ok := peerMutationIface(msg.cmd); ok {
			a.offerSave(iface)
		}
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
		// Cancelling also abandons whatever step a chained flow would take
		// next: nothing runs, so nothing may be waiting on its result.
		a.after = nil
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
	payload := a.input.Payload
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
	case inputNewIfaceName:
		return a, a.wizardTookName(value)
	case inputNewIfaceAddress:
		return a, a.wizardTookAddress(value)
	case inputNewIfacePort:
		return a, a.wizardTookPort(value)
	case inputCreatePreAuthKey:
		return a, a.openConfirmPreAuthKey(value)
	case inputRenameNode:
		id, _ := payload.(string)
		return a, a.openConfirm(wireguard.BuildRenameNode(id, value))
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
		// "N" creates an interface from zero, so it must work on an empty
		// host: it is handled before anything needs a selection.
		if key == "N" {
			if !a.state.WGAvailable {
				a.setStatus(ui.StatusWarn, "no wg on this host — install wireguard-tools first")
				return nil
			}
			return a.startCreateInterface()
		}
		dev, ok := a.selectedDevice()
		if !ok {
			return a.warnNothing()
		}
		switch key {
		case "u":
			return a.openConfirm(wireguard.BuildInterfaceUp(dev.Name))
		case "d":
			return a.openConfirm(wireguard.BuildInterfaceDown(dev.Name))
		case "w":
			a.offerSave(dev.Name)
			return nil
		}
	case wireguard.ScreenPeers:
		switch key {
		case "a":
			if _, ok := a.selectedDevice(); !ok {
				return a.warnNothing()
			}
			a.input = ui.NewInput("Add peer", "PUBLIC-KEY allowed-ip[,allowed-ip]… [psk]", "")
			a.input.Help = "The peer's public key, then its allowed-ips. End with \"psk\" to also " +
				"generate a pre-shared key into a root-only file. A private key is never accepted."
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
		case "w":
			dev, ok := a.selectedDevice()
			if !ok {
				return a.warnNothing()
			}
			a.offerSave(dev.Name)
			return nil
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
		switch key {
		case "e":
			node, ok := a.selectedNode()
			if !ok {
				return a.warnNothing()
			}
			return a.openConfirm(wireguard.BuildExpireNode(node.ID))
		case "x":
			node, ok := a.selectedNode()
			if !ok {
				return a.warnNothing()
			}
			cmd, err := wireguard.BuildDeleteNode(node.ID)
			return a.openConfirmWith(
				"This deletes the node from the control plane. The machine loses "+
					"access and must register again to come back.",
				cmd, err)
		case "m":
			node, ok := a.selectedNode()
			if !ok {
				return a.warnNothing()
			}
			a.input = ui.NewInput("Rename node "+node.ID, "new-name", nodeName(node))
			a.input.Help = "A DNS-label-shaped name: letters, digits and hyphens."
			a.input.Payload = node.ID
			a.inputPurpose = inputRenameNode
			a.mode = modeInput
			return nil
		}
	case wireguard.ScreenKeys:
		if key == "n" {
			if !a.state.Headscale.Present {
				a.setStatus(ui.StatusWarn, "no control plane")
				return nil
			}
			if len(a.state.Headscale.Users) == 0 {
				a.setStatus(ui.StatusWarn, "create a user first — a pre-auth key belongs to one")
				return nil
			}
			a.input = ui.NewInput("Create pre-auth key",
				"user-id [reusable] [ephemeral] [expiration]", a.state.Headscale.Users[0].ID)
			a.input.Help = "The owner's user id (see the users tab), then optional words: " +
				"reusable, ephemeral, and an expiration like 30m, 24h or 7d (default 24h). " +
				"The key is shown once after creation and never stored."
			a.inputPurpose = inputCreatePreAuthKey
			a.mode = modeInput
			return nil
		}
	}
	return nil
}

// startCreateInterface opens the first step of the create-interface wizard.
func (a *app) startCreateInterface() tea.Cmd {
	a.draft.name, a.draft.address, a.draft.port = "", "", ""
	a.input = ui.NewInput("New interface — name", "wg0", "")
	a.input.Help = "The interface to create: its key pair is generated into a root-only file, " +
		"its conf is written to /etc/wireguard, and you can bring it up. Three previewed steps."
	a.inputPurpose = inputNewIfaceName
	a.mode = modeInput
	return nil
}

// wizardTookName validates step 1 and opens step 2.
func (a *app) wizardTookName(name string) tea.Cmd {
	if !wireguard.ValidInterface(name) {
		a.setStatusf(ui.StatusError, "not a valid interface name: %q", name)
		return nil
	}
	if _, exists := a.state.Device(name); exists {
		a.setStatusf(ui.StatusError, "interface %s already exists", name)
		return nil
	}
	a.draft.name = name
	a.input = ui.NewInput("New interface — address", "10.0.0.1/24", "")
	a.input.Help = "The interface's own address, in CIDR form (the Address= line)."
	a.inputPurpose = inputNewIfaceAddress
	a.mode = modeInput
	return nil
}

// wizardTookAddress validates step 2 and opens step 3.
func (a *app) wizardTookAddress(address string) tea.Cmd {
	if !wireguard.ValidCIDR(address) {
		a.setStatusf(ui.StatusError, "not a valid CIDR address: %q", address)
		return nil
	}
	a.draft.address = address
	a.input = ui.NewInput("New interface — listen port", "51820", "51820")
	a.input.Help = "The UDP port the interface listens on."
	a.inputPurpose = inputNewIfacePort
	a.mode = modeInput
	return nil
}

// wizardTookPort validates step 3 and opens the first confirm: the keygen.
// The key pair is generated entirely inside one root shell at the exec site —
// the private key goes straight into a root-only file and only the public key
// comes back.
func (a *app) wizardTookPort(port string) tea.Cmd {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		a.setStatusf(ui.StatusError, "not a valid port: %q", port)
		return nil
	}
	a.draft.port = port
	name := a.draft.name
	keygen, err := wireguard.BuildGenerateInterfaceKey(name)
	cmd := a.openConfirmWith(
		"Step 1 of 3 — generate the key pair for "+name+". The private key is written to "+
			wireguard.KeyPath(name)+" (root, mode 600) inside this one shell and never "+
			"leaves it; only the public key is printed.",
		keygen, err)
	if a.mode == modeConfirm {
		a.after = func(output string) tea.Cmd { return a.confirmWriteConf(lastLine(output)) }
	}
	return cmd
}

// confirmWriteConf is step 2: write the conf file. With the PostUp design the
// file contains no secret, so the dialog can show it whole.
func (a *app) confirmWriteConf(publicKey string) tea.Cmd {
	name, address := a.draft.name, a.draft.address
	port, _ := strconv.Atoi(a.draft.port)
	conf, err := wireguard.InterfaceConf(name, address, port)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	body := "Step 2 of 3 — write " + wireguard.ConfPath(name) + " (mode 600, via stdin). " +
		"It references the key file and contains no private key.\n\n" + conf
	if publicKey != "" {
		body = "Interface public key (share it with peers):\n  " + publicKey + "\n\n" + body
	}
	write, err := wireguard.BuildWriteInterfaceConf(name, conf)
	cmd := a.openConfirmWith(body, write, err)
	if a.mode == modeConfirm {
		a.after = func(string) tea.Cmd { return a.confirmOfferUp(name) }
	}
	return cmd
}

// confirmOfferUp is step 3, and optional: esc leaves the new interface down.
func (a *app) confirmOfferUp(name string) tea.Cmd {
	up, err := wireguard.BuildInterfaceUp(name)
	return a.openConfirmWith(
		"Step 3 of 3 (optional) — bring "+name+" up now. Esc leaves it created but down.",
		up, err)
}

// offerSave opens the confirm for `wg-quick save`, which is how a runtime
// peer change survives the next interface restart.
func (a *app) offerSave(iface string) {
	cmd, err := wireguard.BuildSaveConfig(iface)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return
	}
	_ = a.openConfirmWith(
		"This REWRITES "+wireguard.ConfPath(iface)+" from the runtime state: hand-written "+
			"comments and layout are lost, and wg-quick inlines the private key into the "+
			"file (root-only, mode 600). Esc keeps the change runtime-only.",
		cmd, nil)
}

// openConfirmPreAuthKey parses the pre-auth key input line and opens the
// confirm. The line is the owner's user id plus optional words: reusable,
// ephemeral, and an expiration.
func (a *app) openConfirmPreAuthKey(value string) tea.Cmd {
	fields := strings.Fields(value)
	userID := fields[0]
	reusable, ephemeral := false, false
	expiration := ""
	for _, f := range fields[1:] {
		switch strings.ToLower(f) {
		case "reusable":
			reusable = true
		case "ephemeral":
			ephemeral = true
		default:
			if !wireguard.ValidExpiration(f) {
				a.setStatusf(ui.StatusError, "not a valid option or expiration: %q", f)
				return nil
			}
			expiration = f
		}
	}
	create, err := wireguard.BuildCreatePreAuthKey(userID, reusable, ephemeral, expiration)
	return a.openConfirmWith(
		"Creates a key that lets a machine register itself as this user, without a browser "+
			"login. Headscale prints the key once; this tool shows it once in the status "+
			"line and never stores it.",
		create, err)
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
	return a.openConfirmWith(confirmBody(cmd), cmd, nil)
}

// openConfirmWith is openConfirm with an explicit body, for the dialogs whose
// explanation carries more than the one-liner (a conf file, a warning, a
// one-time-key notice).
func (a *app) openConfirmWith(body string, cmd runner.Command, err error) tea.Cmd {
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title:   cmd.Description,
		Body:    body,
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
	rest := fields[1:]
	// A trailing "psk" asks for a pre-shared key. Its value is generated by a
	// root shell straight into a root-only file at the exec site; only the
	// file PATH ever reaches the add-peer argv, never the key.
	wantPSK := false
	if last := strings.ToLower(rest[len(rest)-1]); last == "psk" {
		wantPSK = true
		rest = rest[:len(rest)-1]
	}
	var ips []string
	for _, f := range rest {
		ips = append(ips, strings.Split(f, ",")...)
	}
	if !wantPSK {
		return a.openConfirm(wireguard.BuildAddPeer(dev.Name, publicKey, ips, ""))
	}
	iface := dev.Name
	genpsk, err := wireguard.BuildGeneratePSK(iface, publicKey)
	cmd := a.openConfirmWith(
		"Step 1 of 2 — generate a pre-shared key into a root-only file. The value never "+
			"leaves that shell; the add-peer step passes wg the file path only.",
		genpsk, err)
	if a.mode == modeConfirm {
		a.after = func(string) tea.Cmd {
			add, err := wireguard.BuildAddPeer(iface, publicKey, ips,
				wireguard.PSKPath(iface, publicKey))
			return a.openConfirmWith(
				"Step 2 of 2 — add the peer. wg opens the pre-shared key file itself; "+
					"the key is never an argument.",
				add, err)
		}
	}
	return cmd
}

// isPreAuthCreate reports whether cmd is the pre-auth key creation, whose
// output is a secret shown exactly once.
func isPreAuthCreate(cmd runner.Command) bool {
	return len(cmd.Argv) >= 3 && cmd.Argv[0] == "headscale" &&
		cmd.Argv[1] == "preauthkeys" && cmd.Argv[2] == "create"
}

// peerMutationIface reports whether cmd added or removed a peer, and on which
// interface, so the save offer can follow it.
func peerMutationIface(cmd runner.Command) (string, bool) {
	argv := cmd.Argv
	if len(argv) >= 5 && argv[0] == "wg" && argv[1] == "set" && argv[3] == "peer" {
		return argv[2], true
	}
	return "", false
}

// lastLine is the final non-empty line of a command's output — where a tool
// that prints one value (a public key, a pre-auth key) puts it.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
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
