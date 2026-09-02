package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-vpn/internal/wireguard"
)

// Layout constants: the rows the table cannot use (header, tab bar, control
// note, table header, help bar, status line).
const (
	headerLines   = 2
	chromeLines   = 5
	minListHeight = 1
)

// controlPlaneNote is the one-line explanation of how identity works, shown on
// every control-plane screen: there is no web admin to log into, because login
// is OIDC in the client's own browser against the IdP.
const controlPlaneNote = "identity: OIDC login in the client's browser against your IdP · the server has no web admin"

// listHeight is the number of table rows that fit on screen. The control-plane
// panel is taller than the one-line note it replaces, so what it costs is
// taken off the table rather than pushing the status line off the bottom.
func (a *app) listHeight() int {
	extra := len(a.noteLines()) - 1
	return max(a.height-headerLines-chromeLines-extra, minListHeight)
}

// View renders the whole screen.
func (a *app) View() string {
	switch a.mode {
	case modeConfirm:
		return a.confirm.View(a.theme, a.width, a.height)
	case modeInput:
		return a.input.View(a.theme, a.width, a.height)
	case modePicker:
		return a.picker.View(a.theme, a.width, a.height)
	case modeHelp:
		return lipgloss.Place(a.width, a.height, lipgloss.Center, lipgloss.Center,
			ui.HelpScreen(a.theme, "tui-vpn — keys", helpKeys(), a.width))
	default:
		return a.browseView()
	}
}

// browseView renders the tabbed main screen: header, tabs, a note on the
// control-plane screens, the table, help bar and status line.
func (a *app) browseView() string {
	var body string
	switch {
	case a.loading && a.rowCount() == 0:
		body = ui.EmptyState(a.theme, "reading…", a.width, a.listHeight()+1)
	case a.loadFailed && a.rowCount() == 0:
		body = ui.EmptyState(a.theme, "could not read — see the message below",
			a.width, a.listHeight()+1)
	case a.rowCount() == 0:
		body = ui.EmptyState(a.theme, a.emptyMessage(), a.width, a.listHeight()+1)
	default:
		body = a.table()
	}

	note := strings.Join(a.noteLines(), "\n")
	help := ui.HelpBar(a.theme, a.shortHelpKeys(), a.width)
	status := ui.StatusLine(a.theme, a.statusKind, a.status, a.defaultStatus(), a.width)
	return strings.Join([]string{a.header(), a.tabsView(), note, body, help, status}, "\n")
}

// noteLines is what sits between the tabs and the table: the identity note on
// every control-plane screen, and above it — on the users screen, which is
// where the control plane is configured from — the panel that answers what the
// note used to leave hanging. "identity is OIDC" is only useful next to which
// IdP, reachable at which URL.
func (a *app) noteLines() []string {
	if !a.onControlPlaneScreen() || !a.state.Headscale.Present {
		return []string{""}
	}
	note := a.theme.Muted.Render(ui.Truncate(controlPlaneNote, a.width))
	if a.screen != wireguard.ScreenUsers {
		return []string{note}
	}
	lines := make([]string, 0, 6)
	for _, line := range a.controlPlanePanel() {
		lines = append(lines, a.theme.Muted.Render(ui.Truncate(line, a.width)))
	}
	return append(lines, note)
}

// controlPlanePanel renders what /etc/headscale/config.yaml says. It is plain
// text rather than a table because these are facts about one thing, not rows.
func (a *app) controlPlanePanel() []string {
	cp := a.state.Headscale.ControlPlane
	head := "control plane · " + orDash(cp.ConfigPath)
	if cp.ServiceState != "" {
		head += " · headscale " + cp.ServiceState
	}
	if !cp.Readable {
		reason := cp.Error
		if reason == "" {
			reason = "not read"
		}
		return []string{head, "  " + reason + " — it must be readable before it can be edited"}
	}
	oidc := cp.OIDC
	server := "  server_url  " + orDash(cp.ServerURL) +
		"   listen_addr " + orDash(cp.ListenAddr)
	if a.serverURLWarning(cp.ServerURL) != "" {
		server += "   ⚠"
	}
	return []string{
		head,
		server,
		"  oidc        issuer " + orDash(oidc.Issuer) +
			" · client_id " + orDash(oidc.ClientID) + " · " + secretState(oidc),
		"  allowed     domains " + listOrDash(oidc.AllowedDomains) +
			" · groups " + listOrDash(oidc.AllowedGroups) +
			" · users " + listOrDash(oidc.AllowedUsers),
		"  scope       " + listOrDash(oidc.Scope) +
			" · pkce " + onOff(oidc.PKCE) +
			" · only_start_if_oidc_is_available " + yesNo(oidc.OnlyStartIfAvailable),
	}
}

// secretState says whether a client secret is configured, and never more than
// that. An inline secret is called out: it is readable by everyone who can read
// config.yaml, which is the reason this tool writes it to its own file.
func secretState(o wireguard.OIDCConfig) string {
	switch {
	case o.ClientSecretInline:
		return "secret INLINE in config.yaml — replace it with O"
	case o.ClientSecretSet:
		return "secret set (" + orDash(o.ClientSecretPath) + ")"
	default:
		return "secret not set"
	}
}

// listOrDash renders a list compactly, or a dash when it is empty.
func listOrDash(items []string) string {
	if len(items) == 0 {
		return "-"
	}
	return strings.Join(items, " ")
}

// onOff renders a boolean as a switch.
func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// onControlPlaneScreen reports whether the current tab is a Headscale one.
func (a *app) onControlPlaneScreen() bool {
	switch a.screen {
	case wireguard.ScreenUsers, wireguard.ScreenNodes, wireguard.ScreenKeys:
		return true
	}
	return false
}

// tabsView renders the five screens as one row, the current one accented.
func (a *app) tabsView() string {
	var parts []string
	for s := wireguard.Screen(0); s < wireguard.ScreenCount; s++ {
		label := " " + s.Title() + " "
		if s == a.screen {
			parts = append(parts, a.theme.Accent.Render(label))
			continue
		}
		parts = append(parts, a.theme.Muted.Render(label))
	}
	return ui.Truncate(strings.Join(parts, a.theme.Muted.Render("│")), a.width)
}

// header renders the facts at the top of the screen.
func (a *app) header() string {
	peers := 0
	for _, d := range a.state.Devices {
		peers += len(d.Peers)
	}
	facts := []ui.Fact{
		{Label: "interfaces", Value: strconv.Itoa(len(a.state.Devices))},
		{Label: "peers", Value: strconv.Itoa(peers)},
	}
	hs := a.state.Headscale
	if hs.Present {
		facts = append(facts,
			ui.Fact{Label: "users", Value: strconv.Itoa(len(hs.Users))},
			ui.Fact{Label: "nodes", Value: strconv.Itoa(len(hs.Nodes))},
			ui.Fact{Label: "oidc", Value: yesNo(hs.OIDCEnabled())})
	} else {
		facts = append(facts, ui.Fact{Label: "headscale", Value: "absent"})
	}
	if wg, ok := compatFor(a.backendCompat, backendWG); ok && wg.Backend != "" {
		facts = append(facts, ui.CompatFact(a.theme, wg))
	}
	return ui.Header{Title: "tui-vpn", Subtitle: a.backend.Describe(), Facts: facts}.
		Render(a.theme, a.width)
}

// defaultStatus is the hint shown when there is no message to report.
func (a *app) defaultStatus() string {
	return strconv.Itoa(a.rowCount()) + " rows  ·  ? for help"
}

// emptyMessage is what a screen shows when it has no rows.
func (a *app) emptyMessage() string {
	switch a.screen {
	case wireguard.ScreenStatus:
		if !a.state.WGAvailable {
			return "no wg found — install wireguard-tools, or run --demo"
		}
		if a.state.WGError != "" {
			return "could not read WireGuard: " + a.state.WGError
		}
		return "no WireGuard interfaces are up"
	case wireguard.ScreenPeers:
		if _, ok := a.selectedDevice(); !ok {
			return "select an interface first"
		}
		return "this interface has no peers"
	case wireguard.ScreenUsers, wireguard.ScreenNodes, wireguard.ScreenKeys:
		if !a.state.Headscale.Present {
			return "no Headscale control plane on this host"
		}
		if a.state.Headscale.Error != "" {
			return "could not read Headscale: " + a.state.Headscale.Error
		}
		return "nothing here yet"
	}
	return "nothing here"
}

// table renders the current screen's table.
func (a *app) table() string {
	columns, rows, styles := a.tableData()
	return ui.Table{
		Columns: columns, Rows: rows, Styles: styles,
		Selected: a.cursor[a.screen], Offset: a.offset[a.screen], Height: a.listHeight(),
	}.Render(a.theme, a.width)
}

// tableData builds the columns, rows and per-row styles for the current screen.
func (a *app) tableData() ([]ui.Column, [][]string, []*lipgloss.Style) {
	switch a.screen {
	case wireguard.ScreenPeers:
		return a.peersTable()
	case wireguard.ScreenUsers:
		return a.usersTable()
	case wireguard.ScreenNodes:
		return a.nodesTable()
	case wireguard.ScreenKeys:
		return a.keysTable()
	default:
		return a.statusTable()
	}
}

func (a *app) statusTable() ([]ui.Column, [][]string, []*lipgloss.Style) {
	columns := []ui.Column{
		{Title: "INTERFACE", Width: 12, Flex: true},
		{Title: "STATE", Width: 6},
		{Title: "PORT", Width: 6},
		{Title: "PEERS", Width: 6},
		{Title: "PUBLIC KEY", Width: 14},
	}
	rows := make([][]string, 0, len(a.state.Devices))
	styles := make([]*lipgloss.Style, 0, len(a.state.Devices))
	for _, d := range a.state.Devices {
		rows = append(rows, []string{
			d.Name, upState(d.Up), portOf(d.ListenPort),
			strconv.Itoa(len(d.Peers)), shortKey(d.PublicKey),
		})
		styles = append(styles, a.stateStyle(d.Up))
	}
	return columns, rows, styles
}

func (a *app) peersTable() ([]ui.Column, [][]string, []*lipgloss.Style) {
	columns := []ui.Column{
		{Title: "PEER", Width: 14},
		{Title: "ENDPOINT", Width: 16, Flex: true},
		{Title: "HANDSHAKE", Width: 12},
		{Title: "TRANSFER", Width: 16},
		{Title: "ALLOWED IPS", Width: 18},
		{Title: "KEEP", Width: 5},
	}
	dev, ok := a.selectedDevice()
	if !ok {
		return columns, nil, nil
	}
	now := time.Now()
	rows := make([][]string, 0, len(dev.Peers))
	styles := make([]*lipgloss.Style, 0, len(dev.Peers))
	for _, p := range dev.Peers {
		rows = append(rows, []string{
			shortKey(p.PublicKey), endpointOr(p.Endpoint),
			handshakeText(now, p.LastHandshake),
			transfer(p.RxBytes, p.TxBytes),
			strings.Join(p.AllowedIPs, ", "),
			keepaliveText(p.Keepalive),
		})
		styles = append(styles, a.handshakeStyle(now, p.LastHandshake))
	}
	return columns, rows, styles
}

func (a *app) usersTable() ([]ui.Column, [][]string, []*lipgloss.Style) {
	columns := []ui.Column{
		{Title: "ID", Width: 4},
		{Title: "NAME", Width: 14, Flex: true},
		{Title: "PROVIDER", Width: 10},
		{Title: "EMAIL", Width: 22},
		{Title: "CREATED", Width: 10},
	}
	users := a.state.Headscale.Users
	now := time.Now()
	rows := make([][]string, 0, len(users))
	for _, u := range users {
		rows = append(rows, []string{
			u.ID, u.Name, orDash(u.Provider), orDash(u.Email), ago(now, u.CreatedAt),
		})
	}
	return columns, rows, nil
}

func (a *app) nodesTable() ([]ui.Column, [][]string, []*lipgloss.Style) {
	columns := []ui.Column{
		{Title: "ID", Width: 4},
		{Title: "NODE", Width: 14, Flex: true},
		{Title: "USER", Width: 10},
		{Title: "ADDRESSES", Width: 18},
		{Title: "LAST SEEN", Width: 11},
		{Title: "STATE", Width: 8},
	}
	nodes := a.state.Headscale.Nodes
	now := time.Now()
	rows := make([][]string, 0, len(nodes))
	styles := make([]*lipgloss.Style, 0, len(nodes))
	for _, n := range nodes {
		rows = append(rows, []string{
			n.ID, nodeName(n), orDash(n.User),
			strings.Join(n.IPAddresses, ", "),
			ago(now, n.LastSeen), nodeState(now, n),
		})
		styles = append(styles, a.nodeStyle(now, n))
	}
	return columns, rows, styles
}

func (a *app) keysTable() ([]ui.Column, [][]string, []*lipgloss.Style) {
	columns := []ui.Column{
		{Title: "ID", Width: 4},
		{Title: "USER", Width: 10, Flex: true},
		{Title: "PREFIX", Width: 12},
		{Title: "REUSABLE", Width: 8},
		{Title: "USED", Width: 5},
		{Title: "EXPIRES", Width: 11},
	}
	keys := a.state.Headscale.PreAuthKeys
	now := time.Now()
	rows := make([][]string, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, []string{
			k.ID, orDash(k.User), orDash(k.KeyPrefix),
			yesNo(k.Reusable), yesNo(k.Used), expiryText(now, k.Expiration),
		})
	}
	return columns, rows, nil
}

// stateStyle colours an interface row by whether it is up.
func (a *app) stateStyle(up bool) *lipgloss.Style {
	if up {
		s := a.theme.Row.Foreground(a.theme.OK.GetForeground())
		return &s
	}
	s := a.theme.Row.Foreground(a.theme.Muted.GetForeground())
	return &s
}

// handshakeStyle colours a peer row: fresh handshakes read OK, a peer that has
// never connected reads muted.
func (a *app) handshakeStyle(now, t time.Time) *lipgloss.Style {
	if t.IsZero() {
		s := a.theme.Row.Foreground(a.theme.Muted.GetForeground())
		return &s
	}
	if now.Sub(t) < 3*time.Minute {
		s := a.theme.Row.Foreground(a.theme.OK.GetForeground())
		return &s
	}
	s := a.theme.Row
	return &s
}

// nodeStyle colours a node row: online reads OK, expired reads danger.
func (a *app) nodeStyle(now time.Time, n wireguard.Node) *lipgloss.Style {
	if !n.Expiry.IsZero() && n.Expiry.Before(now) {
		s := a.theme.Row.Foreground(a.theme.Danger.GetForeground())
		return &s
	}
	if n.Online {
		s := a.theme.Row.Foreground(a.theme.OK.GetForeground())
		return &s
	}
	s := a.theme.Row.Foreground(a.theme.Muted.GetForeground())
	return &s
}

// --- small formatters ---

func upState(up bool) string {
	if up {
		return "up"
	}
	return "down"
}

func portOf(port int) string {
	if port == 0 {
		return "-"
	}
	return strconv.Itoa(port)
}

// shortKey shows enough of a public key to recognise the row, never the whole
// key and never a private one (the model carries no private key).
func shortKey(key string) string {
	if key == "" {
		return "-"
	}
	if len(key) <= 10 {
		return key
	}
	return key[:8] + "…"
}

func endpointOr(e string) string {
	if e == "" {
		return "(never connected)"
	}
	return e
}

func handshakeText(now, t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return ago(now, t)
}

func keepaliveText(seconds int) string {
	if seconds == 0 {
		return "off"
	}
	return strconv.Itoa(seconds) + "s"
}

func nodeName(n wireguard.Node) string {
	if n.GivenName != "" {
		return n.GivenName
	}
	return n.Name
}

func nodeState(now time.Time, n wireguard.Node) string {
	if !n.Expiry.IsZero() && n.Expiry.Before(now) {
		return "expired"
	}
	if n.Online {
		return "online"
	}
	return "offline"
}

func expiryText(now, t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	if t.Before(now) {
		return "expired"
	}
	return "in " + humanDuration(t.Sub(now))
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// transfer renders the rx/tx counters as one compact column.
func transfer(rx, tx int64) string {
	return "↓" + bytesHuman(rx) + " ↑" + bytesHuman(tx)
}

// bytesHuman renders a byte count in the largest unit that keeps it short.
func bytesHuman(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ago renders how long ago a moment was, in one unit.
func ago(now, t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return humanDuration(now.Sub(t)) + " ago"
}

// humanDuration renders a duration in one unit.
func humanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dmin", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// shortHelpKeys is the single-line hint bar, tailored to the current screen.
func (a *app) shortHelpKeys() []ui.KeyHint {
	hints := []ui.KeyHint{{Key: "tab", Desc: "screen"}}
	switch a.screen {
	case wireguard.ScreenStatus:
		hints = append(hints,
			ui.KeyHint{Key: "N", Desc: "new iface"},
			ui.KeyHint{Key: "u", Desc: "up"}, ui.KeyHint{Key: "d", Desc: "down"},
			ui.KeyHint{Key: "w", Desc: "save"})
	case wireguard.ScreenPeers:
		hints = append(hints,
			ui.KeyHint{Key: "a", Desc: "add"}, ui.KeyHint{Key: "x", Desc: "remove"},
			ui.KeyHint{Key: "w", Desc: "save"})
	case wireguard.ScreenUsers:
		hints = append(hints, ui.KeyHint{Key: "n", Desc: "new user"},
			ui.KeyHint{Key: "S", Desc: "server"}, ui.KeyHint{Key: "O", Desc: "oidc"})
	case wireguard.ScreenNodes:
		hints = append(hints,
			ui.KeyHint{Key: "e", Desc: "expire"}, ui.KeyHint{Key: "m", Desc: "rename"},
			ui.KeyHint{Key: "x", Desc: "delete"})
	case wireguard.ScreenKeys:
		hints = append(hints, ui.KeyHint{Key: "n", Desc: "new key"})
	}
	return append(hints,
		ui.KeyHint{Key: "r", Desc: "reload"},
		ui.KeyHint{Key: "?", Desc: "help"},
		ui.KeyHint{Key: "q", Desc: "quit"},
	)
}

// helpKeys is the full key list for the help screen.
func helpKeys() []ui.KeyHint {
	return []ui.KeyHint{
		{Key: "tab / shift+tab", Desc: "next / previous screen"},
		{Key: "1…5", Desc: "jump to a screen"},
		{Key: "↑/k, ↓/j", Desc: "move the selection"},
		{Key: "g / G", Desc: "first / last row"},
		{Key: "pgup/pgdn", Desc: "scroll a page"},
		{Key: "r", Desc: "reload"},
		{Key: "", Desc: ""},
		{Key: "N", Desc: "create a new interface from zero (keygen, conf, up)"},
		{Key: "u / d", Desc: "bring the selected interface up / down"},
		{Key: "w", Desc: "save the interface's runtime config (wg-quick save)"},
		{Key: "a / x", Desc: "add / remove a peer on the interface (add: end with \"psk\""},
		{Key: "", Desc: "to also generate a pre-shared key file)"},
		{Key: "n", Desc: "create a Headscale user (users) / pre-auth key (keys)"},
		{Key: "e / m / x", Desc: "expire / rename / delete the selected node"},
		{Key: "S", Desc: "server settings (users): server_url and listen_addr in"},
		{Key: "", Desc: "/etc/headscale/config.yaml, then a restart"},
		{Key: "O", Desc: "identity provider (users): issuer, client id, secret,"},
		{Key: "", Desc: "allow lists, scope, pkce — then a restart"},
		{Key: "", Desc: ""},
		{Key: "identity", Desc: "login is OIDC in the client's browser against your IdP;"},
		{Key: "", Desc: "the Headscale server exposes no web admin, by design."},
		{Key: "", Desc: "The client secret is typed masked, written to a root-only"},
		{Key: "", Desc: "file, and never shown again — not even to you"},
		{Key: "", Desc: ""},
		{Key: "note", Desc: "every change is previewed and confirmed first"},
		{Key: "keys", Desc: "a private key is never shown, typed, or put on a command line"},
		{Key: "", Desc: ""},
		{Key: "?", Desc: "close this help"},
		{Key: "q", Desc: "quit"},
	}
}
