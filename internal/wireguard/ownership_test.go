package wireguard

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// loadFixture parses a config fixture the way the real backend would.
func loadFixture(t *testing.T, name string) ControlPlane {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name) //nolint:gosec // testdata is in the repository
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	cp, err := ParseHeadscaleConfig(data)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return cp
}

// TestStatePathsFromTheShippedConfig: the packaged file names its state in
// the packaged directory, and the check reads the directory, the key, the
// database with its WAL and SHM, and the tool's own two files.
func TestStatePathsFromTheShippedConfig(t *testing.T) {
	cp := loadFixture(t, "headscale-config.yaml")
	if cp.NoisePrivateKeyPath != "/var/lib/headscale/noise_private.key" {
		t.Errorf("noise key = %q", cp.NoisePrivateKeyPath)
	}
	if cp.DatabasePath != "/var/lib/headscale/db.sqlite" {
		t.Errorf("database = %q", cp.DatabasePath)
	}
	want := []string{
		"/var/lib/headscale",
		"/var/lib/headscale/noise_private.key",
		"/var/lib/headscale/db.sqlite",
		"/var/lib/headscale/db.sqlite-wal",
		"/var/lib/headscale/db.sqlite-shm",
		OIDCClientSecretPath,
		HeadscaleConfigBackupPath,
		HeadscaleConfigPath,
	}
	if got := OwnershipPaths(cp); !reflect.DeepEqual(got, want) {
		t.Errorf("paths =\n%q\nwant\n%q", got, want)
	}
}

// TestStatePathsElsewhere: state outside the packaged directory is checked
// file by file, and its parent directory is NOT — a parent like /srv is not
// headscale's to own.
func TestStatePathsElsewhere(t *testing.T) {
	cp := loadFixture(t, "headscale-config-state-elsewhere.yaml")
	if cp.LegacyPrivateKeyPath != "/srv/headscale/private.key" {
		t.Errorf("legacy key = %q", cp.LegacyPrivateKeyPath)
	}
	paths := OwnershipPaths(cp)
	for _, want := range []string{"/srv/headscale/private.key",
		"/srv/headscale/noise_private.key", "/srv/headscale/db.sqlite"} {
		if !contains(paths, want) {
			t.Errorf("%s is not checked: %q", want, paths)
		}
	}
	if contains(paths, "/srv/headscale") || contains(paths, "/srv") {
		t.Errorf("a directory outside the state directory is checked: %q", paths)
	}
}

// TestStatePathsWithPostgres: a postgres database is not a file here.
func TestStatePathsWithPostgres(t *testing.T) {
	cp := loadFixture(t, "headscale-config-postgres.yaml")
	if cp.DatabasePath != "" {
		t.Errorf("database = %q, want none for postgres", cp.DatabasePath)
	}
	if got := StatePaths(cp); !reflect.DeepEqual(got,
		[]string{"/var/lib/headscale/noise_private.key"}) {
		t.Errorf("state paths = %q", got)
	}
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// TestParseStat reads `stat -c %U:%G:%a:%n` and ignores the lines stat prints
// for a path that does not exist.
func TestParseStat(t *testing.T) {
	out := strings.Join([]string{
		"headscale:headscale:750:/var/lib/headscale",
		"root:root:600:/var/lib/headscale/noise_private.key",
		"stat: cannot statx '/var/lib/headscale/db.sqlite': No such file or directory",
		"root:root:644:/etc/headscale/odd:name.yaml",
		"sudo: a terminal is required to authenticate",
		"",
	}, "\n")
	stats := ParseStat(out)
	if len(stats) != 3 {
		t.Fatalf("stats = %+v, want 3 entries", stats)
	}
	key := stats["/var/lib/headscale/noise_private.key"]
	if key.Owner() != "root:root" || key.Mode != 0o600 {
		t.Errorf("key = %+v", key)
	}
	if _, ok := stats["/etc/headscale/odd:name.yaml"]; !ok {
		t.Error("a path with a colon in it was lost")
	}
}

// stat builds a FileStat for the table below.
func stat(p, owner string, mode uint32) FileStat {
	user, group, _ := strings.Cut(owner, ":")
	return FileStat{Path: p, User: user, Group: group, Mode: mode}
}

// statMap indexes stats by path.
func statMap(stats ...FileStat) map[string]FileStat {
	m := map[string]FileStat{}
	for _, s := range stats {
		m[s.Path] = s
	}
	return m
}

// TestCheckOwnership is the issue's real case and its neighbours.
func TestCheckOwnership(t *testing.T) {
	base := loadFixture(t, "headscale-config.yaml")
	base.ServiceUser, base.ServiceGroup = "headscale", "headscale"

	t.Run("the real case: a root-run configtest before the first start", func(t *testing.T) {
		got := CheckOwnership(base, statMap(
			stat("/var/lib/headscale", "headscale:headscale", 0o750),
			stat("/var/lib/headscale/noise_private.key", "root:root", 0o600),
			stat("/var/lib/headscale/db.sqlite", "root:root", 0o644),
			stat(HeadscaleConfigPath, "root:root", 0o644),
		))
		if !got.Checked || got.OK() || len(got.Issues) != 2 {
			t.Fatalf("ownership = %+v, want the key and the database", got)
		}
		for _, issue := range got.Issues {
			if issue.Role != RoleState || issue.Owner != "root:root" ||
				issue.Want != "headscale:headscale" {
				t.Errorf("issue = %+v", issue)
			}
		}
	})

	t.Run("a fresh install: only the directory exists, and it is right", func(t *testing.T) {
		got := CheckOwnership(base, statMap(
			stat("/var/lib/headscale", "headscale:headscale", 0o750),
			stat(HeadscaleConfigPath, "root:root", 0o644),
		))
		if !got.OK() {
			t.Errorf("ownership = %+v, want OK", got)
		}
	})

	t.Run("the secret file belongs to the service", func(t *testing.T) {
		got := CheckOwnership(base, statMap(
			stat(OIDCClientSecretPath, "root:root", 0o600),
		))
		if len(got.Issues) != 1 || got.Issues[0].Role != RoleSecret {
			t.Errorf("ownership = %+v, want the secret", got)
		}
	})

	t.Run("the backup follows config.yaml, not the service", func(t *testing.T) {
		got := CheckOwnership(base, statMap(
			stat(HeadscaleConfigPath, "root:headscale", 0o640),
			stat(HeadscaleConfigBackupPath, "root:root", 0o644),
		))
		if len(got.Issues) != 1 || got.Issues[0].Role != RoleBackup ||
			got.Issues[0].Want != "root:headscale" {
			t.Errorf("ownership = %+v, want the backup to follow config.yaml", got)
		}
	})

	t.Run("a unit that runs as root is never short of access", func(t *testing.T) {
		root := base
		root.ServiceUser, root.ServiceGroup = "root", "root"
		got := CheckOwnership(root, statMap(
			stat("/var/lib/headscale", "headscale:headscale", 0o750),
			stat("/var/lib/headscale/noise_private.key", "headscale:headscale", 0o600),
			stat(HeadscaleConfigPath, "root:root", 0o644),
		))
		if !got.OK() {
			t.Errorf("ownership = %+v, want OK for a root unit", got)
		}
	})
}

// TestBuildFixOwnership: one recursive chown for the state directory however
// many of its files are wrong, a plain chown for anything else, and nothing
// for a path that could not be trusted on a command line.
func TestBuildFixOwnership(t *testing.T) {
	cmds, err := BuildFixOwnership([]OwnershipIssue{
		{Path: "/etc/headscale/config.yaml.bak", Role: RoleBackup, Owner: "root:root", Want: "root:headscale"},
		{Path: OIDCClientSecretPath, Role: RoleSecret, Owner: "root:root", Want: "headscale:headscale"},
		{Path: "/srv/headscale/db.sqlite", Role: RoleState, Owner: "root:root", Want: "headscale:headscale"},
		{Path: "/var/lib/headscale/db.sqlite", Role: RoleState, Owner: "root:root", Want: "headscale:headscale"},
		{Path: "/var/lib/headscale/noise_private.key", Role: RoleState, Owner: "root:root", Want: "headscale:headscale"},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var got []string
	for _, c := range cmds {
		got = append(got, c.String())
		if c.Stdin != "" {
			t.Errorf("%q carries stdin", c.String())
		}
	}
	want := []string{
		"chown root:headscale /etc/headscale/config.yaml.bak",
		"chown headscale:headscale " + OIDCClientSecretPath,
		"chown headscale:headscale /srv/headscale/db.sqlite",
		"chown -R headscale:headscale /var/lib/headscale",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("commands =\n%q\nwant\n%q", got, want)
	}

	for _, bad := range []OwnershipIssue{
		{Path: "relative/db.sqlite", Role: RoleState, Want: "headscale:headscale"},
		{Path: "/var/lib/headscale/-rf", Role: RoleState, Want: "headscale:headscale"},
		{Path: "/var/lib/headscale/../../etc", Role: RoleState, Want: "headscale:headscale"},
		{Path: "/var/lib/headscale/a b", Role: RoleState, Want: "headscale:headscale"},
		{Path: "/var/lib/headscale/db.sqlite", Role: RoleState, Want: "UNKNOWN:headscale"},
	} {
		if _, err := BuildFixOwnership([]OwnershipIssue{bad}); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
}

func TestReadableBy(t *testing.T) {
	for _, tc := range []struct {
		st          FileStat
		user, group string
		want        bool
	}{
		{stat("/c", "headscale:headscale", 0o600), "headscale", "headscale", true},
		{stat("/c", "root:headscale", 0o640), "headscale", "headscale", true},
		{stat("/c", "root:root", 0o600), "headscale", "headscale", false},
		{stat("/c", "root:root", 0o644), "headscale", "headscale", true},
		{stat("/c", "root:headscale", 0o600), "headscale", "headscale", false},
		{stat("/c", "root:root", 0o600), "root", "root", true},
	} {
		if got := tc.st.ReadableBy(tc.user, tc.group); got != tc.want {
			t.Errorf("%+v ReadableBy(%s:%s) = %v, want %v", tc.st, tc.user, tc.group, got, tc.want)
		}
	}
}
