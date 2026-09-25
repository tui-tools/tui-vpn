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
| `ip-route.json` | **Captured** on the same VM (`ip -j route`), with its addresses moved into the documentation ranges and the docker bridge's network too. |

## Keys and addresses

**Every key in these fixtures is an obviously invented placeholder and every
address is from a documentation range**, and the test suite enforces both:

- Addresses are loopback, the wildcard, or one of `192.0.2.0/24`,
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
