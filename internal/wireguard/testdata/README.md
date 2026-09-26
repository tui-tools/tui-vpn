# Fixtures

Every parser in this package is tested against a captured or a carefully
constructed sample, because a parser tested only against what its author
imagined is a parser that works on one machine. What is in here, and where it
came from:

| File | Source |
| --- | --- |
| `wg-show-all-dump.txt` | **Constructed** from the documented `wg show all dump` format (`wireguard-tools`, `wg(8)`). The machine this was written on has `wg` but no interface up, so there was nothing to capture; the first machine in the lab with a live interface should replace it with a real, scrubbed capture. Two interfaces, one with a mid-handshake peer, a never-connected peer, and a pre-shared key. |
| `iptables-cloud-image.txt` | **Captured**, unmodified, on a real Ubuntu 24.04 cloud VM: `iptables -S` of the provider's image with docker installed. INPUT and FORWARD both end in `-j REJECT`, the WireGuard port is not accepted, and the provider's own chain carries quoted `--comment`s. The only addresses in it are link-local (the metadata service), which name no machine. |
| `iptables-ufw.txt` | **Constructed** in ufw's shape: policy DROP, jumps into user chains, a multiport range, a rate-limited rule, a rule for one source only and a RETURN. |
| `nft-firewalld-closed.json`, `nft-firewalld-open.json` | **Captured**, unmodified, in the lab on Fedora 44 Cloud (firewalld 2.4.4, nftables 1.1.6, default zone `public` with ssh, mdns and dhcpv6-client): `nft -j list ruleset` before and after `firewall-cmd --add-port=51820/udp`. The case of issue #28: firewalld's rules live in its own `inet firewalld` table, which `iptables -S` never lists. The only addresses in them are firewalld's own (multicast groups, link-local, the 6to4 filter under `2002::/16`), the same on every machine. |
| `tui-firewall-firewalld-closed.json`, `tui-firewall-firewalld-open.json` | **Captured**, unmodified, on the same guest: `tui-firewall --check` (0.6.1) with the port removed and added. Zones as tui-firewall models them: a target, and services, ports and bindings with their runtime or permanent scope. |
| `nft-ufw.json`, `tui-firewall-ufw.json` | **Captured**, unmodified, in the lab on Ubuntu 26.04 (ufw 0.36.2 on iptables-nft, only 22/tcp allowed): `nft -j list ruleset` and `tui-firewall --check`. ufw's input hook is nothing but jumps into its own chains. |
| `firewalld-zones.txt`, `firewalld-policies-default.txt`, `firewalld-policies-forwarding.txt` | **Constructed** in the exact shape of `firewall-cmd --list-all-zones` and `--list-all-policies` (firewalld 2.x): the zones of a Fedora host with the default zone `public` bound to `ens3`, the stock `allow-host-ipv6` policy alone, and the same plus the `wg0-fwd` policy a forwarding server's PostUp builds (issue #30), with the peers' and the destination networks in documentation ranges. |
| `firewalld-f44-policies-stock.txt`, `firewalld-f44-policies-forwarding.txt`, `firewalld-f44-zones-forwarding.txt` | **Captured** from firewalld 2.4.4 on Fedora 44 (a privileged Fedora 44 container running systemd and firewalld, standing in for the lab guest): `firewall-cmd --list-all-policies` before, and `--list-all-policies` / `--list-all-zones` while a forwarding server created by this tool was up (`wg0` bound to `public`, the `wg0-fwd` policy). Fedora's five `gateway-*` policies are listed `(disabled)`. The only change: the peers' and the destination networks in the rich rules were moved into documentation ranges. |
| `ip-route.json` | **Captured** on the same VM (`ip -j route`), with its addresses moved into the documentation ranges and the docker bridge's network too. |

## Keys and addresses

**Every key in these fixtures is an obviously invented placeholder and every
address is from a documentation range**, and the test suite enforces both:

- Addresses are loopback, the wildcard, link-local, or one of `192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737) and `2001:db8::/32`
  (RFC 3849). `TestFixturesCarryNoRealAddress` decodes each fixture the way the
  parsers do and fails on anything else.
- WireGuard keys are runs of a single letter or the base64 of readable ASCII.
- `TestFixturesCarryNoHostName` checks that no fixture carries the host name of
  whatever machine the suite runs on.

## Adding one

Paste the output that broke, scrub the keys to obvious placeholders and the
addresses into the documentation ranges above, and add a case to the table
test. A parser that is wrong on somebody's machine is fixed by making their
output the next fixture.
