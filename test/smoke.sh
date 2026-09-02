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

check "check --demo names the server URL" \
  "$bin --demo --check" \
  '"serverUrl": "https://vpn\.example\.com"'

check "check --demo names the OIDC issuer" \
  "$bin --demo --check" \
  '"oidcIssuer": "https://idp\.example\.com'

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

echo "--- tui-vpn: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
