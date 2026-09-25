#!/bin/bash
# Backend smoke test for tui-wireguard, run inside a lab guest.
#
# The contract (see tui-tools/tui-lab): this script runs on the guest as the
# unprivileged lab user, escalates with `sudo -n` only, prints a short PASS/FAIL
# table and exits non-zero if anything failed. The binary under test is at
# $TUI_LAB_BIN (default: tui-wireguard on PATH).
#
# What a smoke test proves is that the tool reads the machine's *real* subject
# and agrees with the machine's own tooling — not that a fake renders. The
# template has no real subject worth asserting on, so what is here is the part
# every tool shares: the --report block. Add yours next to it, and add a
# record_compat that appends the probed version to compat/results.jsonl.
set -uo pipefail

bin="${TUI_LAB_BIN:-tui-wireguard}"
pass=0
fail=0

# check runs one assertion. It takes a label, a command and a grep pattern the
# command's output must match. Output is captured so a failure can show it.
check() {
  local label="$1" command="$2" pattern="$3" output status
  output=$(eval "$command" 2>&1)
  status=$?
  if [[ $status -eq 0 ]] && grep -qE "$pattern" <<<"$output"; then
    printf 'PASS  %s\n' "$label"
    pass=$((pass + 1))
  else
    printf 'FAIL  %s (exit %d)\n' "$label" "$status"
    sed 's/^/      | /' <<<"$output" | head -12
    fail=$((fail + 1))
  fi
}

echo "--- tui-wireguard smoke on $(. /etc/os-release && echo "$PRETTY_NAME")"
echo "      user=$(id -un)"

# --- the report block ------------------------------------------------------
#
# --report is read-only and unprivileged, so it is smoked without sudo: a user
# who cannot escalate is exactly the one who most needs to be able to file a
# usable bug. What is asserted is that it names the backend this machine is
# actually driving, that it still answers under --demo, and that it keeps its
# privacy promise — the block goes into a public issue, so a home path or the
# host name appearing in it is a bug, not a cosmetic detail.
check "report names the backend" \
  "$bin --report" \
  '^backend: wireguard'

check "report says the run was live" \
  "$bin --report" \
  '^mode: live$'

check "report carries the wireguard-tools fact" \
  "$bin --report" \
  '^wireguard-tools: '

check "report carries the interface count" \
  "$bin --report" \
  '^wg interfaces: '

check "report works in demo mode too" \
  "$bin --demo --report" \
  '^backend: demo$'

check "and says so on the mode line" \
  "$bin --demo --report" \
  '^mode: demo'

# The distro and kernel lines are quoted from the machine's own description of
# itself, and a host named after its distribution ("fedora" on Fedora) would
# match there without anything having leaked. They are dropped before the
# search, so this stays a test of the tool rather than of the guest's hostname.
check "report leaks neither a home path nor the host name" \
  "$bin --report | grep -vE '^(distro|kernel): ' | grep -cE '/home/|$(uname -n)' || true" \
  '^0$'

# --- the check block -------------------------------------------------------
#
# --check reads once and prints JSON. Under --demo it runs with nothing
# installed, so it is the read path that is always exercisable in the lab. It
# must carry no key, no endpoint and no address of the host — only counts.
check "check --demo is valid JSON naming the demo backend" \
  "$bin --demo --check" \
  '"backend": "demo"'

check "check --demo has no control-plane block (Headscale moved to tui-tailscale)" \
  "$bin --demo --check | grep -cE '\"(headscale|controlPlane)\"' || true" \
  '^0$'

check "check --demo leaks no demo endpoint address" \
  "$bin --demo --check | grep -cE '198\.51\.100\.|192\.0\.2\.' || true" \
  '^0$'

# --- the host firewall -----------------------------------------------------
#
# A WireGuard server behind an INPUT chain that ends in REJECT takes no
# handshake, and one whose FORWARD chain ends in REJECT forwards nothing. The
# demo's interface has its port open and forwards; on a real host the ruleset
# is read through sudo -n, and a read that failed says "unknown", never
# "accept".
check "check --demo says the demo interface's port is accepted" \
  "$bin --demo --check" \
  '"listenPortInput": "accept"'

check "check --demo says the demo interface forwards" \
  "$bin --demo --check" \
  '"forwarding": true'

if command -v iptables >/dev/null 2>&1 && sudo -n iptables -S >/dev/null 2>&1; then
  check "check read the host firewall" \
    "sudo -n $bin --check" \
    '"firewallChecked": true'
fi

# The whole promise, on the real read path: --check goes into public issues,
# so a URL anywhere in it is a bug.
check "check carries no URL of this host" \
  "$bin --check | grep -c '://' || true" \
  '^0$'

check "check without privilege reports the firewall as unread, not open" \
  "$bin --sudo '' --check | grep -c '\"listenPortInput\": \"accept\"' || true" \
  '^0$'

# --- the real subject ------------------------------------------------------
#
# The interfaces --check counts have to be the ones wg itself lists, each
# with the peer count and listen port wg reports. Asserted only where wg can
# be read, which needs sudo -n.
if command -v wg >/dev/null 2>&1 && sudo -n wg show interfaces >/dev/null 2>&1; then
  ifaces=$(sudo -n wg show interfaces | wc -w)
  check "check counts the interfaces wg lists ($ifaces)" \
    "sudo -n $bin --check | grep -c '\"hasPrivateKey\"' || true" \
    "^${ifaces}\$"
  for iface in $(sudo -n wg show interfaces); do
    port=$(sudo -n wg show "$iface" listen-port)
    peers=$(sudo -n wg show "$iface" peers | grep -c . || true)
    check "check agrees with wg about $iface (port $port, $peers peers)" \
      "sudo -n $bin --check | tr -d ' \n' | grep -oE '\"name\":\"$iface\"[^}]*\"listenPort\":$port,[^}]*\"peerCount\":$peers' || true" \
      "$iface"
  done
fi

# The configuration of the old name is still read after an upgrade from
# tui-vpn, and the tool says so. Only checked when the lab left one behind.
if [[ -r /etc/tui-vpn/config.toml ]]; then
  check "report names the legacy tui-vpn config it read" \
    "$bin --report" \
    'old tui-vpn config /etc/tui-vpn/config.toml'
fi

# --- compatibility evidence ------------------------------------------------
#
# record_compat turns this run into the evidence `tested` is generated from:
# one line per backend whose version the tool itself probed, printed behind
# `compat-result:` so it survives the trip out of the guest in the lab's log,
# and appended to $TUI_COMPAT_RESULTS as well for a run outside the lab.
# --check's compat block is a list: each entry names a backend and, when the
# probe could read one, its version.
TOOL=tui-wireguard
record_compat() {
  local report="$1" outcome="$2" distro today backend version line
  distro=$(. /etc/os-release && echo "${ID}-${VERSION_ID:-rolling}")
  today=$(date -u +%Y-%m-%d)
  local recorded=0
  while IFS=$'\t' read -r backend version; do
    [[ -n $backend && -n $version ]] || continue
    line=$(printf '{"backend":"%s","date":"%s","distro":"%s","result":"%s","suite":"smoke","tool":"%s","version":"%s"}' \
      "$backend" "$today" "$distro" "$outcome" "$TOOL" "$version")
    printf 'compat-result: %s\n' "$line"
    if [[ -n ${TUI_COMPAT_RESULTS:-} ]]; then
      printf '%s\n' "$line" >>"$TUI_COMPAT_RESULTS"
    fi
    recorded=$((recorded + 1))
  done < <(sed -n '/"compat": \[/,/^  \]/p' <<<"$report" | awk '
    /"backend":/ { if (b != "") print b "\t" v; gsub(/.*"backend": "|".*/, ""); b = $0; v = "" }
    /"version":/ { gsub(/.*"version": "|".*/, ""); v = $0 }
    END { if (b != "") print b "\t" v }')
  if [[ $recorded -eq 0 ]]; then
    echo "      no version was probed, so no compatibility result is recorded"
  fi
}

outcome=pass
[[ $fail -eq 0 ]] || outcome=fail
record_compat "$(sudo -n "$bin" --check 2>/dev/null)" "$outcome"

echo "--- tui-wireguard: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
