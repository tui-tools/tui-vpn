# Fixtures

Every parser in this package is tested against a captured or a carefully
constructed sample, because a parser tested only against what its author
imagined is a parser that works on one machine. What is in here, and where it
came from:

| File | Source |
| --- | --- |
| `wg-show-all-dump.txt` | **Constructed** from the documented `wg show all dump` format (`wireguard-tools`, `wg(8)`). The machine this was written on has `wg` but no interface up, so there was nothing to capture; the first machine in the lab with a live interface should replace it with a real, scrubbed capture. Two interfaces, one with a mid-handshake peer, a never-connected peer, and a pre-shared key. |
| `headscale-users.json` | **Constructed** from `headscale users list --output json` (the protojson form of the `User` message). Two OIDC users. |
| `headscale-nodes.json` | **Constructed** from `headscale nodes list --output json`. Three nodes: one online, one offline, one already expired; two registered via OIDC, one via a pre-auth key. |
| `headscale-preauthkeys.json` | **Constructed** from `headscale preauthkeys list --output json`. One reusable key. |

Headscale is not installed on this machine, so all three control-plane fixtures
are constructed rather than captured. The first lab host with a real Headscale
and an IdP should replace them with scrubbed captures.

## Keys and addresses

**Every key in these fixtures is an obviously invented placeholder and every
address is from a documentation range**, and the test suite enforces both:

- Addresses are loopback, the wildcard, or one of `192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737) and `2001:db8::/32`
  (RFC 3849). `TestFixturesCarryNoRealAddress` decodes each fixture the way the
  parsers do and fails on anything else.
- WireGuard keys are runs of a single letter or the base64 of readable ASCII;
  Headscale machine/node/disco keys are runs of a single digit. A pre-auth
  key's value never survives the parser at all — only its prefix is kept.
- `TestFixturesCarryNoHostName` checks that no fixture carries the host name of
  whatever machine the suite runs on.

## Adding one

Paste the output that broke, scrub the keys to obvious placeholders and the
addresses into the documentation ranges above, and add a case to the table
test. A parser that is wrong on somebody's machine is fixed by making their
output the next fixture.
