<img src="assets/logo.png" alt="tui-tools" width="240">

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/tui-tools/tui-vpn/badge)](https://scorecard.dev/viewer/?uri=github.com/tui-tools/tui-vpn)

> **Beta, and unreleased.** This tool is private while its control-plane path is validated against a real Headscale and an IdP in the lab. Flags and keys may move without notice.

# tui-vpn

WireGuard and its control plane, from the terminal.

tui-vpn reads the WireGuard interfaces on a host straight from `wg show all dump` — peers, endpoints, the latest handshake, transfer counters, allowed IPs and keepalive — and, when a self-hosted [Headscale](https://headscale.net) control plane is present, the users, nodes and pre-authentication keys that decide who is allowed onto the network.

It manages as well as reads. Creating an interface from zero, bringing one up or down, adding or removing a peer, saving the runtime config, expiring, renaming or deleting a node, creating a user or a pre-auth key — every change is shown as the exact command line first and applied only after you confirm it. There is one place a process is ever started, `internal/wireguard`, so the command the dialog showed is provably the command that runs.

## Identity is OIDC, not a web admin

User login is deliberately not in this tool. Identity is OpenID Connect, done in the client's own browser against your IdP; Headscale mirrors the users and nodes the IdP authorises. The Headscale server exposes no web admin, which is the whole point of the design — there is no console to log into, and tui-vpn does not pretend to be one.

What tui-vpn does own is the *configuration* of that identity. See [Identity provider (OIDC)](#identity-provider-oidc) below: `S` and `O` on the users screen write `/etc/headscale/config.yaml` for you, previewing the exact lines they change.

A private key is never shown, typed, or put on a command line. Adding a peer needs only its public key; a pre-shared key is passed to `wg` as a file it opens itself, never as an argument (a command line is visible in `ps` to every user on the machine).

## Try it with nothing installed

```sh
tui-vpn --demo
```

`--demo` runs every screen against a fake WireGuard and a fake Headscale: one interface with two peers — one mid-handshake, one that has never connected — and a control plane with two users, three nodes and a pre-auth key. Nothing on the host is read and nothing is changed.

## Screens

`tab` (or `1`…`5`) switches between them:

![The status screen: WireGuard interfaces, their state and peer counts](docs/screenshots/tui-vpn-status.png)

- **interfaces** — the WireGuard interfaces on this host, with peer counts and state. `N` creates one from zero, `u` / `d` bring one up or down, `w` saves its runtime config.
- **peers** — the peers of the selected interface: endpoint, handshake age, transfer, allowed-ips, keepalive. `a` / `x` add or remove a peer (end the add line with `psk` to also generate a pre-shared key file); `w` saves.
- **users** — the Headscale users, and the provider they authenticate against, under a panel showing what `/etc/headscale/config.yaml` says: `server_url`, `listen_addr`, `dns.base_domain`, the transport and the OIDC redirect URI it implies, the OIDC issuer and client id, whether a client secret is set, the allow lists, and the state of the `headscale` unit: active or not, enabled at boot or not, the account it runs as, and whether that account owns its state files. `n` creates a user; `S` and `O` configure the control plane; `F` fixes the ownership of headscale's files.
- **nodes** — the machines registered with Headscale, who owns each, and key expiry. `e` expires one, `m` renames one, `x` deletes one.
- **preauth keys** — the keys that let a machine register itself, shown by prefix only. `n` creates one, shown exactly once.

![The peers screen: endpoints, handshake age and transfer for the selected interface](docs/screenshots/tui-vpn-peers.png)

![The users screen, under the control-plane panel: the unit's state and account, file ownership, server_url, transport, base domain, the OIDC redirect URI, issuer and client id, and that a client secret is set](docs/screenshots/tui-vpn-users.png)

The panel is the answer to what the identity note used to leave hanging: which IdP, reachable at which URL, and whether a secret is set — never what it is.

![The Headscale nodes screen: who owns each node and its state, above the OIDC identity note](docs/screenshots/tui-vpn-headscale.png)

Every mutation opens a confirm dialog with the exact command before it runs.

![The help screen: keys, and how identity works over OIDC](docs/screenshots/tui-vpn-help.png)

## Manage, not view

Beyond up/down and peer add/remove, tui-vpn can bootstrap and maintain a WireGuard host — always through the same rule: preview the exact command, confirm, run.

### Create an interface from zero (`N`)

On an empty host, `N` on the interfaces screen walks a three-step wizard: name, address (CIDR) and listen port, then three previewed commands.

1. **Keygen** — one root shell: `sh -c 'umask 077 && wg genkey | tee /etc/wireguard/<if>.key | wg pubkey'`. The private key is written straight into a root-only file inside that shell and never leaves it; only the public key comes back, shown so you can hand it to peers.
2. **Write the conf** — the file is fed to `install -m 600 /dev/stdin /etc/wireguard/<if>.conf` on stdin, so its content never rides an argv. The conf deliberately contains **no private key**: it carries `PostUp = wg set %i private-key /etc/wireguard/<if>.key`, so wg-quick loads the key from its file at up time. That is why the confirm dialog can show you the whole file.
3. **Bring it up** — the usual `wg-quick up`, optional; esc leaves the interface created but down.

### Persist peer changes (`w`)

`wg set` mutations are runtime-only. After a successful peer add or remove, tui-vpn offers `wg-quick save <if>`; `w` on the interfaces or peers screen offers it on demand. The dialog warns before you confirm: the save **rewrites** the conf from runtime state (hand-written comments are lost, and wg-quick inlines the private key into the root-only, mode 600 file — standard wg-quick behaviour).

### Optional pre-shared key on add-peer

End the add-peer line with `psk` and tui-vpn first previews a root shell that generates `wg genpsk` into a root-only file, then previews the add-peer command passing `wg` that file **path**. The key value never appears on a command line or on screen.

### Pre-auth keys (`n` on the keys screen)

Pick the owning user by id and optionally add the words `reusable`, `ephemeral` and an expiration like `30m`, `24h` or `7d` (default `24h`). The previewed command is `headscale preauthkeys create --user <id> [--reusable] [--ephemeral] --expiration <dur>`. Headscale prints the key once; tui-vpn shows it once in the status line with a "shown once — copy it now" note and never stores it. The list keeps showing prefixes only, like headscale's own CLI.

### Server settings (`S` on the users screen)

`S` is how clients reach the control plane. It starts with the **transport**, because the transport decides what every later answer means, and writes only the lines that transport needs into `/etc/headscale/config.yaml`:

| Transport | `server_url` | `listen_addr` | What else is written | What is cleared |
| --- | --- | --- | --- | --- |
| **plain http** | `http://`, an IP or a name | proposed as `0.0.0.0:<the URL's port>` | nothing | `tls_letsencrypt_hostname`, `tls_cert_path`, `tls_key_path` |
| **Let's Encrypt** | `https://` and a public DNS name; an IP is refused | `0.0.0.0:443` | `tls_letsencrypt_hostname` (the URL's host), `tls_letsencrypt_challenge_type` (`TLS-ALPN-01` when port 80 is closed, `HTTP-01` otherwise), `acme_email` (optional) | `tls_cert_path`, `tls_key_path` |
| **own certificate** | `https://` and the name on the certificate | `0.0.0.0:443` | `tls_cert_path`, `tls_key_path` | `tls_letsencrypt_hostname` |
| **reverse proxy** | `https://` and the name the proxy serves | loopback, refused otherwise | nothing: TLS ends at the proxy | `tls_letsencrypt_hostname`, `tls_cert_path`, `tls_key_path` |

"Cleared" means emptied where the file already has the key, and left alone where it does not: switching from Let's Encrypt to plain http empties `tls_letsencrypt_hostname`, so headscale stops asking for a certificate nobody wants, and a file that never had the key gains no empty line.

Every transport ends with **`dns.base_domain`**, the MagicDNS domain nodes are named under. It is checked the way headscale checks it at startup: a valid DNS name, required while `dns.magic_dns` is on, and not a suffix of the `server_url` host (MagicDNS owns every name under it, so clients could not reach the control plane, and headscale refuses to start).

A refused answer reopens its own step with the reason on top and what you typed still in it.

**The host is checked, not only the characters.** headscale does not validate the host of `server_url`, so a public IP typed with one digit too many (`http://203.0.113.1000:443`) used to be written and served, and every client then failed on a DNS lookup for a name that looks like an address. A host has to be an IP address that parses, or a DNS name whose last label is not all digits (no top-level domain is numeric). The same check applies to `listen_addr`'s address part and to the OIDC issuer, and a malformed value already in the file is flagged in the panel and shown with its problem when `S` proposes it.

**Plain http is a real option, not a mistake.** The Tailscale control protocol runs over Noise, so everything between clients and headscale is encrypted and authenticated whatever the URL scheme. The one thing that needs https is a browser: an OIDC login redirects to `<server_url>/oidc/callback`, and Google and most other IdPs refuse a redirect URI that is plain http or names a raw IP. So the panel explains plain http instead of warning about it, and only when OIDC is configured do the form and the confirm dialog say, before and after the answer, that browser logins will fail. The panel also shows that redirect URI, next to whether an IdP will accept it, because it is the value an OAuth client has to be registered with.

The painless case, a server reached by IP: pick **plain http**, type `http://203.0.113.10:443`, accept the proposed `0.0.0.0:443`, and give a private base domain such as `tailnet.internal`. The diff is three lines.

**An own certificate is checked before it is written.** The form `stat`s the certificate, the key and every directory above them from this machine, and refuses a pair the account headscale runs as cannot reach, naming the file or directory in the way. The pair [tui-cert](https://github.com/tui-tools/tui-cert) issues lives in its root-only `/etc/ssl/tui-cert`, which a `headscale` user cannot enter: its install step copies the pair wherever the service can read it. A path under `/home` or `/tmp` gets a warning, because the packaged unit hides those trees from the service. [tui-firewall](https://github.com/tui-tools/tui-firewall) opens the port, or port 80 for `HTTP-01`.

The confirm dialog shows a **diff of the changed lines and nothing else** (a value already in the file, however it is quoted, is not a change), then the write, then the step that makes headscale read it as a separate, optional confirm (see [The last step: restart, or enable](#the-last-step-restart-or-enable)).

### The last step: restart, or enable

`S` and `O` both end by making headscale read the new configuration, and what that takes depends on the unit, which the panel shows next to its active state (`headscale active · enabled`):

| The unit is | The last step previews |
| --- | --- |
| enabled (or static, indirect: anything that already starts at boot) | `systemctl restart headscale` |
| disabled and not running, which is how a fresh package install leaves it | `systemctl enable --now headscale` |
| disabled but running, started by hand | `systemctl enable headscale`, then `systemctl restart headscale` as its own confirm |

A disabled unit is the trap: a restart brings the control plane up now, and it is gone after the next reboot. `enable --now` would not help the third row either, because it leaves a running unit alone and the new configuration would never be read. Esc at any of these steps leaves the file written and the unit as it was.

### Identity provider (OIDC)

`O` on the users screen configures the whole `oidc:` section: issuer URL, client id, client secret, allowed domains, allowed groups, allowed users, scope (`openid profile email` by default), `only_start_if_oidc_is_available` and `pkce.enabled`.

**What is written where.** Two files, and only two:

| File | What lands in it | Mode |
| --- | --- | --- |
| `/etc/headscale/config.yaml` | every OIDC setting **except** the secret, plus `client_secret_path` pointing at the file below | unchanged (the write truncates in place and keeps the existing owner and mode; a `.bak` copy is taken first) |
| `/etc/headscale/oidc_client_secret` | the client secret, and nothing else | `600`, owned by the account the `headscale` unit runs as, created atomically by `install -o … -g … -m 600` |

**The secret is never shown.** It is typed with the echo masked, travels to the exec site on the command's **standard input** — never on an argv, which is visible in `ps` to every user on the machine — and is dropped from the tool's memory the moment the write command exists, cancelled flows included. It is not in the confirm dialog, not in the status line, not in the diff, and not in `config.yaml`: headscale reads it from the file through `client_secret_path`. The tool will not read it back either; the most it will ever say is `secret set`. When a secret is already configured, leaving the field empty keeps it, and typing a new one replaces it.

A secret found sitting *inline* in `config.yaml` — someone else's setup, or an older one — is flagged in the panel and emptied by the next `O`, because headscale refuses to start with both a secret and a secret path, and because a credential has no business being in a configuration file. The diff redacts that line rather than printing it.

**The diff is minimal, by construction.** `config.yaml` is not re-serialised: it is parsed only to *locate* each key, then spliced line by line, so comments, blank lines, key order and every section the change does not touch survive byte for byte. The lines the dialog shows are provably the only lines that differ.

**The issuer is checked before saving.** tui-vpn fetches `<issuer>/.well-known/openid-configuration` with `curl` **from the server itself** — the machine that will have to reach the IdP — and reports what it found. A failure is a warning, not a refusal: an IdP that is down this minute is not a reason to be unable to write down its address.

**Then a restart.** A configuration change does nothing until the unit that reads it restarts, so the flow ends with `systemctl restart headscale` as its own confirm, or with the enable a disabled unit needs (see [the last step](#the-last-step-restart-or-enable)). Esc there leaves the file written and the running server on the old settings.

**The secret file is owned by the service, not by root.** tui-vpn reads `systemctl show headscale -p User -p Group` and hands the file to that account in the same previewed `install`, so there is no second step and no window in which the ownership is wrong. It matters because units disagree: headscale's own `.deb` (0.29.3, checked on a real Ubuntu 24.04 host) and the Arch package run it as a dedicated `headscale` user, while a hand-written or older unit may run it as root — and a root-only secret file would leave a `headscale`-user service unable to read its own credential and unable to come back from the restart at the end of the flow. A unit that names no user gets `root:root`, which is what systemd would have used anyway. The mode stays `600` in every case: the owner is what changes, so the file is readable by exactly one account either way. The panel shows which account that is, next to the unit's state.

### State ownership (`F` on the users screen)

A common way to break a fresh control plane without noticing: run `sudo headscale configtest` (or any `headscale` subcommand) as root before the first start. That creates the noise private key and the SQLite database owned by `root`, while the packaged unit runs as `User=headscale`, and the service then fails at the restart that ends `S` or `O` with nothing pointing at the cause. systemd's `StateDirectory=` does not help: it fixes the owner of `/var/lib/headscale` itself, not of the files already inside it.

So the panel checks. It reads the unit's `User`/`Group` (the same read the secret file uses) and `stat`s:

| Path | Should belong to |
| --- | --- |
| `/var/lib/headscale`, and the directories under it that hold the files below | the account the unit runs as |
| `noise.private_key_path` (and a pre-0.23 top-level `private_key_path`) | the account the unit runs as |
| `database.sqlite.path`, with its `-wal` and `-shm` files (not checked for postgres) | the account the unit runs as |
| `/etc/headscale/oidc_client_secret`, which `O` writes | the account the unit runs as |
| `/etc/headscale/config.yaml.bak`, which every write takes | whoever owns `config.yaml`: it holds the same content, so no more and no less readable |

A path that does not exist yet is not a problem, and a unit that runs as root is never short of access, so only the backup is compared there. A mismatch shows next to the service state (`ownership ⚠ /var/lib/headscale/noise_private.key is root:root, want headscale:headscale — F fixes it`), and `F` previews the fix, one confirm per command:

- every mismatch inside `/var/lib/headscale` is covered by **one** `chown -R <user>:<group> /var/lib/headscale`, because a root-run headscale leaves more behind than the files the check names, and the whole directory belongs to the service anyway;
- a state file `config.yaml` puts anywhere else gets its own `chown <user>:<group> <file>`, never a recursive one: a database at `/srv/db.sqlite` must not turn into a `chown -R` of `/srv`;
- the secret file and the backup get a plain `chown` each.

The chain ends with the same restart (or enable) step as `S` and `O`, since a service that failed on these files needs one. `--check` reports the result as `ownershipChecked`, `ownershipOk` and `ownershipIssues` (path, role, current and wanted owner); an ownership that could not be read is reported as unchecked, never as fine.

### Node rename and delete (`m` / `x`)

`m` renames the selected node (DNS-label names) via `headscale nodes rename --identifier <id> <name>`; `x` deletes it via `headscale nodes delete --identifier <id> --force` — `--force` because tui-vpn's own confirm dialog is the prompt, and it is painted as a danger dialog.

All of the above works under `--demo` too, against the fake backend, with nothing installed and nothing changed.

## `--report`, for bug reports

```sh
tui-vpn --report
```

Prints the versions and machine facts a bug report needs and exits — no UI, no privileges, and nothing about you: no private key, no public key of this host, no endpoint address. It names the versions of the two backends it drives (`wg` and `headscale`), whether this host runs a WireGuard interface, and whether a control plane is present. It runs even on a machine with neither installed, so "there is nothing here to drive" is itself a filable report.

## `--check`, one read as JSON

```sh
tui-vpn --check
```

Reads the interfaces and the control plane once and prints a summary as JSON: interface and peer counts, per-peer handshake ages, whether Headscale is present, user and node counts, and a `compat` block naming each backend's version.

It also carries a `controlPlane` block read from `/etc/headscale/config.yaml`: `serviceState` and `serviceEnabled` (what `systemctl is-active` and `is-enabled` answer for the unit), `serviceAccount`, the ownership check (`ownershipChecked`, `ownershipOk`, `ownershipIssues`), `oidcClientId`, the scope, whether a client secret is set, and the answers below. `oidcConfigured` now comes from that configuration rather than being guessed; the older guess — inferred from users carrying a provider and nodes registered through OIDC — stays as `oidcInferred`, which is the answer used on a host whose `config.yaml` cannot be read.

Like `--report`, it carries **no key, no endpoint, no URL and no address of the host** — and the control-plane block is no exception. What an "OIDC does not work" report actually needs is the two ways the setup fails, not the URL that names your server, so:

| Instead of | `--check` prints |
| --- | --- |
| `server_url` | `serverUrlSet`, `serverUrlHttps`, `serverUrlLoopback` and `serverUrlIsIp` — the questions worth asking, as booleans — and `transport` (`plain-http`, `letsencrypt`, `own-cert` or `reverse-proxy`) |
| `listen_addr` | `listenPort` and `listenLoopback`, because a bind address can name an internal interface |
| the OIDC issuer URL | `oidcIssuer`, reduced to the issuer's **host name** — which IdP, without the realm and path that describe your internal layout |

`baseDomain` is printed as it is, like the issuer's host: it is the tailnet's own naming, and `baseDomainConflict` answers whether headscale would refuse to start over it. The allow lists are counted rather than printed, because they name people, and the client secret has no field at all — only `oidcClientSecretSet`. `test/smoke.sh` asserts that no `://` survives anywhere in the output.

<!-- install:start -->
<!-- Generated by tui-kit/tools/render-install.py from tool.json. -->
<!-- Edit the manifest, then run `make readme`. -->

### From source

```sh
git clone https://github.com/tui-tools/tui-vpn
cd tui-vpn && make demo
```

Not packaged for these yet; the static binary works everywhere in the meantime.

### Arch Linux — coming soon

Needs the tui-tools repository, which is a [one-time
setup](https://tui.tools/install/).

The one-liner detects the distribution and adds the repository and its signing
key:

```sh
curl -fsSL https://pkgs.tui.tools/install.sh | sh
```

Piping a script into a shell is not this family's style, so here is the same
setup by hand — read it, or read the script first with `curl -fsSL
https://pkgs.tui.tools/install.sh -o install.sh`:

```sh
curl -fsSL -o /tmp/tui-tools.asc https://pkgs.tui.tools/pubkey.asc
sudo pacman-key --add /tmp/tui-tools.asc
sudo pacman-key --lsign-key \
  "$(gpg --show-keys --with-colons /tmp/tui-tools.asc | awk -F: '/^fpr:/{print $10; exit}')"
printf '[tui-tools]\nServer = https://pkgs.tui.tools/arch/$arch\n' \
  | sudo tee -a /etc/pacman.conf
sudo pacman -Sy
```

Then, and for every other tool in the family:

```sh
sudo pacman -S tui-vpn
```

Available once the first release lands in pkgs.tui.tools.

### Debian and Ubuntu — coming soon

Needs the tui-tools repository, which is a [one-time
setup](https://tui.tools/install/).

The one-liner detects the distribution and adds the repository and its signing
key:

```sh
curl -fsSL https://pkgs.tui.tools/install.sh | sh
```

Piping a script into a shell is not this family's style, so here is the same
setup by hand — read it, or read the script first with `curl -fsSL
https://pkgs.tui.tools/install.sh -o install.sh`:

```sh
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://pkgs.tui.tools/pubkey.asc \
  | sudo gpg --dearmor -o /etc/apt/keyrings/tui-tools.gpg
echo "deb [signed-by=/etc/apt/keyrings/tui-tools.gpg] https://pkgs.tui.tools/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/tui-tools.list
sudo apt update
```

Then, and for every other tool in the family:

```sh
sudo apt install tui-vpn
```

Available once the first release lands in pkgs.tui.tools.

### Fedora and RHEL — coming soon

Needs the tui-tools repository, which is a [one-time
setup](https://tui.tools/install/).

The one-liner detects the distribution and adds the repository and its signing
key:

```sh
curl -fsSL https://pkgs.tui.tools/install.sh | sh
```

Piping a script into a shell is not this family's style, so here is the same
setup by hand — read it, or read the script first with `curl -fsSL
https://pkgs.tui.tools/install.sh -o install.sh`:

```sh
sudo rpm --import https://pkgs.tui.tools/pubkey.asc
sudo curl -fsSL -o /etc/yum.repos.d/tui-tools.repo https://pkgs.tui.tools/rpm/tui-tools.repo
sudo dnf makecache
```

Then, and for every other tool in the family:

```sh
sudo dnf install tui-vpn
```

Available once the first release lands in pkgs.tui.tools.

### Any distribution, static binary — coming soon

```sh
curl -fsSL https://github.com/tui-tools/tui-vpn/releases/download/v0.3.0/tui-vpn_0.3.0_linux_amd64.tar.gz | tar -xz tui-vpn
sudo install -m0755 tui-vpn /usr/local/bin/tui-vpn
```

Available once the first release is tagged.

### Verify a download

Every release of `tui-vpn` ships a `checksums.txt`. Check an archive against it
before installing:

```sh
sha256sum -c checksums.txt --ignore-missing
```

Website: https://tui.tools/tools/tui-vpn/
<!-- install:end -->

<!-- compat:start -->
<!-- Generated by tui-kit/tools/render-compat.py from tool.json. -->
<!-- Edit the manifest, then run `make readme`. -->

`tui-vpn` probes its backend once at startup and shows the version in the
header. A version nobody has tested is marked `(untested)` there rather than
hidden; one below the minimum is marked as such and the tool still runs.

### wireguard-tools

| | |
| --- | --- |
| Binary | `wg` |
| Version read with | `wg --version` |
| Minimum | 1.0.20200513 |
| Tested | `1.0.20210914` |

### headscale

| | |
| --- | --- |
| Binary | `headscale` |
| Version read with | `headscale version` |
| Minimum | 0.22.0 |
| Tested | `0.29.3` |

| Versions | What changes |
| --- | --- |
| `<0.23` | `preauthkeys list` requires a `--user`, so the pre-auth keys screen may be empty; users and nodes are unaffected |

The tested versions are generated from `compat/results.jsonl`, which the tool's
own smoke test appends to when it runs against a real machine in
[tui-lab](https://github.com/tui-tools/tui-lab).
<!-- compat:end -->

## Phase 2: OpenVPN

OpenVPN is a planned second backend, with [openvpn-auth-oauth2](https://github.com/jkroepke/openvpn-auth-oauth2) for its OAuth2 story. It is not part of this phase.

## License

MIT. See [LICENSE](LICENSE).
