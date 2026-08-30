package main

import (
	"context"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/manifest"
	tuivpn "github.com/tui-tools/tui-vpn"
)

// The two backends this tool drives that carry a version worth classifying:
// wireguard-tools (wg) and headscale. wg-quick and ip ship with those and are
// not probed separately.
const (
	backendWG        = "wireguard-tools"
	backendHeadscale = "headscale"
)

// probeCompat reads the version of each backend the manifest declares and
// classifies it against what has been tested. The results go in the header,
// --check and --report. It never fails: a missing binary, a hung process or
// unparsable output all end as the "version unknown" badge, because a
// compatibility probe that can stop a tool from starting is worse than none.
func probeCompat(ctx context.Context, demo bool) []compat.Result {
	// --demo drives an in-memory network, so probing the host would report
	// versions that have nothing to do with what is on screen.
	if demo {
		return nil
	}
	m, err := manifest.Load(tuivpn.ManifestJSON)
	if err != nil {
		return nil
	}
	var results []compat.Result
	for _, name := range []string{backendWG, backendHeadscale} {
		backend, ok := m.Backend(name)
		if !ok {
			continue
		}
		results = append(results, compat.Probe(ctx, backend))
	}
	return results
}

// compatFor returns the probed result for one backend, if it was probed.
func compatFor(results []compat.Result, backend string) (compat.Result, bool) {
	for _, r := range results {
		if r.Backend == backend {
			return r, true
		}
	}
	return compat.Result{}, false
}
