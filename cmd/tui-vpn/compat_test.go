package main

import (
	"context"
	"testing"

	"github.com/tui-tools/tui-kit/manifest"
	tuivpn "github.com/tui-tools/tui-vpn"
)

// The embedded manifest is what the header, --check and --report read. This
// tool declares two backends, and both have to parse.
func TestEmbeddedManifestDeclaresItsBackends(t *testing.T) {
	m, err := manifest.Load(tuivpn.ManifestJSON)
	if err != nil {
		t.Fatalf("the embedded tool.json does not parse: %v", err)
	}
	if m.Name != toolName {
		t.Errorf("manifest name = %q, want %q", m.Name, toolName)
	}
	for _, name := range []string{backendWG, backendHeadscale} {
		backend, ok := m.Backend(name)
		if !ok {
			t.Fatalf("no %s backend in the manifest", name)
		}
		if len(backend.VersionCommand) == 0 {
			t.Errorf("%s declares no version command", name)
		}
	}
}

func TestProbeCompatSkipsDemo(t *testing.T) {
	if got := probeCompat(context.Background(), true); got != nil {
		t.Errorf("demo probe = %+v, want nil", got)
	}
}

// The probe runs against whatever this machine has. It must produce a result
// for each declared backend either way — a compatibility probe never fails.
func TestProbeCompatOnThisMachine(t *testing.T) {
	got := probeCompat(context.Background(), false)
	if len(got) != 2 {
		t.Fatalf("got %d results, want 2 (one per backend)", len(got))
	}
	if _, ok := compatFor(got, backendWG); !ok {
		t.Errorf("no wireguard-tools result: %+v", got)
	}
	for _, r := range got {
		t.Logf("this machine: %s %s (%s)", r.Backend, r.Version, r.Status)
	}
}
