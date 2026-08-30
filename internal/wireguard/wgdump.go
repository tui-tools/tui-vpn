package wireguard

import (
	"strconv"
	"strings"
	"time"
)

// ParseWgDump turns the output of `wg show all dump` into a list of devices.
//
// The dump is tab-separated and line-oriented. The first line of each interface
// describes the interface itself; the lines after it are its peers, until the
// next interface begins. In the `all` form every line is prefixed with the
// interface name, which is how a peer line (nine fields) is told from an
// interface line (five):
//
//	<iface> <private-key> <public-key> <listen-port> <fwmark>
//	<iface> <public-key> <preshared-key> <endpoint> <allowed-ips> <handshake> <rx> <tx> <keepalive>
//
// Absent values arrive as the literal "(none)" or "off". The private key is
// read only to record that one exists — it is never stored or returned.
//
// A line that does not have one of the two expected field counts is skipped
// rather than failing the parse: the dump can be read while it changes, and a
// tool that shows most of the truth is better than one that shows an error.
func ParseWgDump(dump string) []Device {
	var devices []Device
	// index remembers where each interface landed, so a peer line can be
	// appended to the interface that owns it whatever order they arrive in.
	index := map[string]int{}

	for _, line := range strings.Split(dump, "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		switch len(fields) {
		case 5:
			// Interface line: iface, private, public, listen-port, fwmark.
			name := fields[0]
			if name == "" {
				continue
			}
			dev := Device{
				Name:          name,
				HasPrivateKey: notNone(fields[1]),
				PublicKey:     cleanKey(fields[2]),
				ListenPort:    max(atoi(fields[3]), 0),
				FwMark:        fields[4],
				Up:            true,
			}
			if i, ok := index[name]; ok {
				// Keep any peers already parsed for this interface.
				dev.Peers = devices[i].Peers
				devices[i] = dev
			} else {
				index[name] = len(devices)
				devices = append(devices, dev)
			}
		case 9:
			// Peer line.
			name := fields[0]
			if name == "" {
				// A peer with no interface belongs to nothing; skip it rather
				// than inventing a nameless device.
				continue
			}
			peer := Peer{
				PublicKey:       cleanKey(fields[1]),
				HasPresharedKey: notNone(fields[2]),
				Endpoint:        endpoint(fields[3]),
				AllowedIPs:      allowedIPs(fields[4]),
				LastHandshake:   handshake(fields[5]),
				RxBytes:         nonNeg64(atoi64(fields[6])),
				TxBytes:         nonNeg64(atoi64(fields[7])),
				Keepalive:       max(keepalive(fields[8]), 0),
			}
			i, ok := index[name]
			if !ok {
				// A peer for an interface whose header has not been seen: keep
				// it anyway, under a stub the header line will complete.
				index[name] = len(devices)
				i = len(devices)
				devices = append(devices, Device{Name: name, Up: true})
			}
			devices[i].Peers = append(devices[i].Peers, peer)
		default:
			// Not a line this dump produces.
			continue
		}
	}
	return devices
}

// notNone reports whether a field carries a value rather than "(none)".
func notNone(s string) bool { return s != "" && s != "(none)" }

// cleanKey returns the key, or "" for the "(none)" placeholder.
func cleanKey(s string) string {
	if s == "(none)" {
		return ""
	}
	return s
}

// endpoint returns the peer endpoint, or "" when it has never connected.
func endpoint(s string) string {
	if s == "(none)" {
		return ""
	}
	return s
}

// allowedIPs splits the comma-separated allowed-ips field.
func allowedIPs(s string) []string {
	if s == "" || s == "(none)" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// handshake turns the unix-seconds field into a time; 0 means never.
func handshake(s string) time.Time {
	secs := atoi64(s)
	if secs <= 0 {
		return time.Time{}
	}
	return time.Unix(secs, 0)
}

// keepalive turns the field into seconds; "off" is 0.
func keepalive(s string) int {
	if s == "off" || s == "" {
		return 0
	}
	return atoi(s)
}

// atoi parses an int, returning 0 for anything unparseable.
func atoi(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

// atoi64 parses an int64, returning 0 for anything unparseable.
func atoi64(s string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// nonNeg64 clamps a counter to zero: wg never reports a negative transfer, so a
// negative value is malformed input, not a number to keep.
func nonNeg64(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}
