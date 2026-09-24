#!/bin/bash
# Backend smoke test for tui-vpn, run inside a lab guest.
#
# The contract (see tui-tools/tui-lab): this script runs on the guest as the
# unprivileged lab user, escalates with `sudo -n` only, prints a short PASS/FAIL
# table and exits non-zero if anything failed. The binary under test is at
# $TUI_LAB_BIN (default: tui-vpn on PATH).
#
# What a smoke test proves is that the tool reads the machine's *real* subject
# and agrees with the machine's own tooling — not that a fake renders. The
# template has no real subject worth asserting on, so what is here is the part
# every tool shares: the --report block. Add yours next to it, and add a
# record_compat that appends the probed version to compat/results.jsonl.
set -uo pipefail

bin="${TUI_LAB_BIN:-tui-vpn}"
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

echo "--- tui-vpn smoke on $(. /etc/os-release && echo "$PRETTY_NAME")"
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

check "report carries the headscale fact" \
  "$bin --report" \
  '^headscale: '

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

check "check --demo reports the control plane as OIDC-configured" \
  "$bin --demo --check" \
  '"oidcConfigured": true'

check "check --demo leaks no demo endpoint address" \
  "$bin --demo --check | grep -cE '198\.51\.100\.|192\.0\.2\.' || true" \
  '^0$'

# --- the control-plane block -----------------------------------------------
#
# The configuration read is what turned `oidc: yes/no` from a guess into a
# fact, so the block that carries it is smoked here. Under --demo it is the
# sample configuration; on a real router it is /etc/headscale/config.yaml.
check "check --demo carries the control-plane block" \
  "$bin --demo --check" \
  '"controlPlane"'

# The server_url is answered as two booleans rather than printed: those are the
# two ways an otherwise healthy setup fails, and neither names this host.
check "check --demo answers the server_url questions" \
  "$bin --demo --check" \
  '"serverUrlHttps": true'

check "check --demo says whether the server_url is loopback" \
  "$bin --demo --check" \
  '"serverUrlLoopback": false'

check "check --demo reduces the OIDC issuer to its host" \
  "$bin --demo --check" \
  '"oidcIssuer": "idp\.example\.com"'

# The whole promise, on the real read path this time: --check goes into public
# issues, so a URL anywhere in it is a bug.
check "check carries no URL of this host" \
  "$bin --check | grep -c '://' || true" \
  '^0$'

check "check --demo carries no URL either" \
  "$bin --demo --check | grep -c '://' || true" \
  '^0$'

# Whether the unit starts at boot is the half of "is it running" a fresh
# install gets wrong: the package leaves it disabled.
check "check --demo says whether the unit starts at boot" \
  "$bin --demo --check" \
  '"serviceEnabled": "disabled"'

# On a machine with headscale installed, the same fact comes from the real
# unit, and has to agree with systemd's own answer.
if command -v headscale >/dev/null 2>&1; then
  enabled=$(systemctl is-enabled headscale 2>/dev/null | head -1)
  check "check agrees with systemctl about the unit starting at boot" \
    "sudo -n $bin --check" \
    "\"serviceEnabled\": \"${enabled:-unknown}\""
fi

# The ownership check: the demo's noise key is root's, the way a root-run
# `headscale configtest` leaves it, and --check names the path.
check "check --demo names a state file the service account does not own" \
  "$bin --demo --check" \
  '"path": "/var/lib/headscale/noise_private.key"'

# On a machine with headscale, the check has to have run (stat reached the
# state directory through sudo -n) and agree with stat about the directory.
if command -v headscale >/dev/null 2>&1; then
  check "check ran the ownership check on the real state directory" \
    "sudo -n $bin --check" \
    '"ownershipChecked": true'

  owner=$(sudo -n stat -c %U:%G /var/lib/headscale 2>/dev/null)
  account=$(systemctl show headscale -p User --value 2>/dev/null)
  if [[ -n $owner && -n $account && ${owner%%:*} != "$account" ]]; then
    check "check reports the state directory owned by the wrong account" \
      "sudo -n $bin --check" \
      '"path": "/var/lib/headscale"'
  elif [[ -n $owner ]]; then
    check "check does not flag a state directory the service owns" \
      "sudo -n $bin --check | grep -c '\"path\": \"/var/lib/headscale\"' || true" \
      '^0$'
  fi
fi

# The transport, read from the TLS settings and the bind: the demo sits behind
# a reverse proxy, with a MagicDNS domain outside its server_url host.
check "check --demo names the transport" \
  "$bin --demo --check" \
  '"transport": "reverse-proxy"'

check "check --demo reports the base domain without a conflict" \
  "$bin --demo --check" \
  '"baseDomainConflict": false'

if command -v headscale >/dev/null 2>&1; then
  check "check reads a transport from the real configuration" \
    "sudo -n $bin --check" \
    '"transport": "(plain-http|letsencrypt|own-cert|reverse-proxy)"'
fi

check "check --demo keeps the inference as a separate field" \
  "$bin --demo --check" \
  '"oidcInferred":'

# The whole point of writing the secret to its own file: --check can say that
# one is set and has no field that could carry the value. A JSON key whose name
# is client-secret-ish and whose value is a string would be a bug.
check "check --demo reports the secret as set, never its value" \
  "$bin --demo --check" \
  '"oidcClientSecretSet": true'

check "check --demo has no field that could hold a secret" \
  "$bin --demo --check | grep -icE '\"(oidc)?[a-z]*clientsecret\": \"' || true" \
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

check "check without privilege reports the firewall as unread, not open" \
  "$bin --sudo '' --check | grep -c '\"listenPortInput\": \"accept\"' || true" \
  '^0$'

# --- node routes -----------------------------------------------------------
#
# A subnet router's routes stay pending until approved; --check counts them per
# node and never prints the networks.
check "check --demo counts the demo router's pending exit node" \
  "$bin --demo --check" \
  '"exitNode": "pending"'

check "check --demo prints no route" \
  "$bin --demo --check | grep -cE '0\.0\.0\.0/0|203\.0\.113\.' || true" \
  '^0$'

# --- compatibility evidence ------------------------------------------------
#
# record_compat turns this run into the evidence `tested` is generated from:
# one line per backend whose version the tool itself probed, printed behind
# `compat-result:` so it survives the trip out of the guest in the lab's log,
# and appended to $TUI_COMPAT_RESULTS as well for a run outside the lab.
# tui-vpn drives two backends, so --check's compat block is a list: each
# entry names a backend and, when the probe could read one, its version.
TOOL=tui-vpn
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

echo "--- tui-vpn: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
