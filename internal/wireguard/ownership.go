package wireguard

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-kit/runner"
)

// This file answers the question a failed restart leaves hanging: can the
// account headscale runs as actually read and write its own files?
//
// The case it exists for is common and silent. Before the first start,
// someone runs `sudo headscale configtest` (or any headscale subcommand) as
// root. That creates the noise private key and the SQLite database owned by
// root, while the packaged unit runs as its own `headscale` user. systemd's
// StateDirectory= only fixes the ownership of the directory itself when that
// is wrong, not of what is already inside it, so the service then fails at the
// restart that ends S or O with nothing on screen pointing at the cause.
//
// The check reads owner, group and mode of the paths config.yaml names for
// headscale's state, and of the two files this tool writes itself: the
// config.yaml backup and the OIDC client secret. A mismatch is shown in the
// panel with a previewed `chown` as the fix.

// HeadscaleStateDir is the state directory the packaged unit declares
// (StateDirectory=headscale) and the one place a recursive chown is ever
// offered for. A path config.yaml names outside it is fixed one file at a
// time, never recursively: a database configured at /srv/db.sqlite must not
// turn into `chown -R` of /srv.
const HeadscaleStateDir = "/var/lib/headscale"

// FileStat is one path's owner, group and permission bits, as `stat` reports
// them.
type FileStat struct {
	Path  string
	User  string
	Group string
	Mode  uint32
}

// Owner renders the owner the way chown takes it.
func (s FileStat) Owner() string { return s.User + ":" + s.Group }

// ReadableBy reports whether an account can read the file, going by the owner
// and mode alone. Supplementary groups are not considered: the check is
// conservative, and a file it calls unreadable can be made readable by giving
// it to the account outright.
func (s FileStat) ReadableBy(user, group string) bool {
	switch {
	case user == DefaultServiceUser:
		return true
	case s.User == user:
		return s.Mode&0o400 != 0
	case s.Group == group:
		return s.Mode&0o040 != 0
	default:
		return s.Mode&0o004 != 0
	}
}

// OwnershipRole says why a path is checked, which decides who should own it.
type OwnershipRole string

const (
	// RoleState is a file or directory headscale reads and writes at run time:
	// it must belong to the account the unit runs as.
	RoleState OwnershipRole = "state"
	// RoleSecret is the OIDC client secret file this tool writes: mode 600,
	// so it must belong to that same account or the service cannot read it.
	RoleSecret OwnershipRole = "secret"
	// RoleBackup is the config.yaml backup this tool takes before a write. It
	// holds the same content as config.yaml, so it should have the same owner
	// as config.yaml: no more readable, and no less.
	RoleBackup OwnershipRole = "backup"
)

// OwnershipIssue is one path that is not owned the way it should be.
type OwnershipIssue struct {
	Path string        `json:"path"`
	Role OwnershipRole `json:"role"`
	// Owner is who owns it now, Want who should, both as user:group.
	Owner string `json:"owner"`
	Want  string `json:"want"`
}

// Ownership is the result of the check.
type Ownership struct {
	// Checked reports that the paths could be read at all. An unchecked
	// ownership is not a clean one, and is never reported as one.
	Checked bool `json:"checked"`
	// Issues lists every path whose owner is not the expected one.
	Issues []OwnershipIssue `json:"issues,omitempty"`
}

// OK reports a check that ran and found nothing to fix.
func (o Ownership) OK() bool { return o.Checked && len(o.Issues) == 0 }

// StatePaths lists the state files config.yaml names: the noise private key
// (and the pre-0.23 top-level private key, when an old file still sets one),
// and the SQLite database with its write-ahead log and shared-memory files,
// which a root-run headscale creates root-owned along with it.
func StatePaths(cp ControlPlane) []string {
	var paths []string
	for _, p := range []string{cp.NoisePrivateKeyPath, cp.LegacyPrivateKeyPath} {
		if ValidStatePath(p) {
			paths = append(paths, p)
		}
	}
	if ValidStatePath(cp.DatabasePath) {
		paths = append(paths, cp.DatabasePath, cp.DatabasePath+"-wal", cp.DatabasePath+"-shm")
	}
	return paths
}

// OwnershipPaths is every path the check reads: the state directory, the
// state files and the directories inside it that hold them, the tool's own
// secret and backup files, and config.yaml itself, which the backup is
// compared against. Missing paths are fine: `stat` skips them, and so does the
// check.
func OwnershipPaths(cp ControlPlane) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	add(HeadscaleStateDir)
	for _, p := range StatePaths(cp) {
		add(p)
		if dir := path.Dir(p); InsideStateDir(dir) {
			add(dir)
		}
	}
	add(OIDCClientSecretPath)
	add(HeadscaleConfigBackupPath)
	add(HeadscaleConfigPath)
	return out
}

// statFormat is what `stat -c` prints per path: owner, group, octal mode and
// the name last, so a path with a colon in it still parses.
const statFormat = "%U:%G:%a:%n"

// StatArgv is the read behind the check. It escalates: the state directory is
// mode 750 and owned by the service account, so only root sees inside it.
func StatArgv(paths []string) []string {
	return append([]string{"stat", "-c", statFormat, "--"}, paths...)
}

// ParseStat reads the output of StatArgv. The lines `stat` prints for a path
// that does not exist ("stat: cannot statx …") do not have the shape and are
// skipped, which is what makes a missing path a non-event.
func ParseStat(out string) map[string]FileStat {
	stats := map[string]FileStat{}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 4)
		if len(parts) != 4 || !strings.HasPrefix(parts[3], "/") {
			continue
		}
		mode, err := strconv.ParseUint(parts[2], 8, 32)
		if err != nil {
			continue
		}
		stats[parts[3]] = FileStat{Path: parts[3], User: parts[0], Group: parts[1],
			Mode: uint32(mode)}
	}
	return stats
}

// CheckOwnership compares what `stat` found with who should own each path.
//
// A unit that runs as root is never short of access, so it has nothing to fix
// on the state and secret side; the backup is still compared with config.yaml,
// because that is about who else can read it, not about the service.
func CheckOwnership(cp ControlPlane, stats map[string]FileStat) Ownership {
	result := Ownership{Checked: true}
	user, group := cp.ServiceUser, cp.ServiceGroup
	if user == "" {
		user = DefaultServiceUser
	}
	if group == "" {
		group = user
	}
	want := user + ":" + group

	flag := func(p string, role OwnershipRole, expected string) {
		st, ok := stats[p]
		if !ok || st.Owner() == expected {
			return
		}
		result.Issues = append(result.Issues, OwnershipIssue{
			Path: p, Role: role, Owner: st.Owner(), Want: expected})
	}

	if user != DefaultServiceUser {
		for _, p := range OwnershipPaths(cp) {
			switch p {
			case OIDCClientSecretPath:
				flag(p, RoleSecret, want)
			case HeadscaleConfigBackupPath, HeadscaleConfigPath:
				// Compared below, against config.yaml rather than the
				// service; config.yaml itself is not this check's business.
			default:
				flag(p, RoleState, want)
			}
		}
	}
	if cfg, ok := stats[HeadscaleConfigPath]; ok {
		flag(HeadscaleConfigBackupPath, RoleBackup, cfg.Owner())
	}
	sort.SliceStable(result.Issues, func(i, j int) bool {
		return result.Issues[i].Path < result.Issues[j].Path
	})
	return result
}

// InsideStateDir reports whether p is the state directory or below it.
func InsideStateDir(p string) bool {
	p = path.Clean(p)
	return p == HeadscaleStateDir || strings.HasPrefix(p, HeadscaleStateDir+"/")
}

// statePathPattern is an absolute path with nothing in it that could become a
// second argument or need quoting. These paths come from config.yaml and end
// up in a chown argv, so anything unusual is left alone rather than trusted.
var statePathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/@+-]*$`)

// ValidStatePath reports whether p is an absolute, clean, plain path.
func ValidStatePath(p string) bool {
	return p != "" && statePathPattern.MatchString(p) && path.Clean(p) == p &&
		!strings.Contains(p, "/-")
}

// BuildFixOwnership assembles the chowns that fix the issues, in the order
// they should be confirmed:
//
//   - every state path inside the state directory is covered by ONE
//     `chown -R <user>:<group> /var/lib/headscale`: a root-run headscale
//     leaves more behind than the files the check names (the WAL, caches),
//     and the whole directory belongs to the service anyway;
//   - a state file config.yaml puts elsewhere gets its own, non-recursive
//     chown, because recursing from a directory this tool does not own could
//     hand far more than headscale's files to the service;
//   - the secret file goes to the service account, and the backup to
//     config.yaml's owner.
func BuildFixOwnership(issues []OwnershipIssue) ([]runner.Command, error) {
	var cmds []runner.Command
	recursive := ""
	for _, issue := range issues {
		if !ValidStatePath(issue.Path) {
			return nil, fmt.Errorf("refusing to chown an unusual path: %q", issue.Path)
		}
		user, group, ok := strings.Cut(issue.Want, ":")
		if !ok || !ValidAccountName(user) || !ValidAccountName(group) {
			return nil, fmt.Errorf("not a valid owner: %q", issue.Want)
		}
		switch {
		case issue.Role == RoleState && InsideStateDir(issue.Path):
			if recursive == "" {
				recursive = issue.Want
				cmds = append(cmds, runner.Command{
					Argv: []string{"chown", "-R", issue.Want, HeadscaleStateDir},
					Description: "Give " + HeadscaleStateDir + " back to " + issue.Want +
						", recursively",
				})
			}
		default:
			cmds = append(cmds, runner.Command{
				Argv:        []string{"chown", issue.Want, issue.Path},
				Description: "Give " + issue.Path + " to " + issue.Want,
			})
		}
	}
	return cmds, nil
}
