package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"somegit.dev/ALHP/ALHP.GO/ent"
)

const (
	testBaseRabbitmq   = "rabbitmq"
	testPkgRabbitmqAdm = "rabbitmqadmin"
)

func pkginfo(pkgname, pkgbase string) []byte {
	body := "pkgname = " + pkgname + "\n"
	if pkgbase != "" {
		body += "pkgbase = " + pkgbase + "\n"
	}
	return []byte(body + "pkgver = 1.0-1\narch = x86_64\n")
}

func TestPackagePkgbase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		members []tarMember
		want    string
		wantErr bool
	}{
		{
			name: "pkgbase matches pkgname",
			members: []tarMember{
				{Name: pkginfoName, Content: pkginfo("foo", "foo")},
				{Name: "usr/bin/foo", Content: []byte("payload")},
			},
			want: "foo",
		},
		{
			// the case the whole change exists for: the filename says one thing
			// and the owning pkgbase says another
			name: "split package reports its base",
			members: []tarMember{
				{Name: pkginfoName, Content: pkginfo(testPkgRabbitmqAdm, testBaseRabbitmq)},
				{Name: "usr/bin/rabbitmqadmin", Content: []byte("payload")},
			},
			want: testBaseRabbitmq,
		},
		{
			name: "no pkgbase line",
			members: []tarMember{
				{Name: pkginfoName, Content: pkginfo("foo", "")},
			},
			wantErr: true,
		},
		{
			name: "no .PKGINFO at all",
			members: []tarMember{
				{Name: "usr/bin/foo", Content: []byte("payload")},
			},
			wantErr: true,
		},
		{
			// makepkg writes .PKGINFO third, after .BUILDINFO and .MTREE, so
			// anything that buries it deeper is not one of ours and must not cost
			// a full archive walk to reject
			name:    "beyond the member bound",
			members: buriedPkginfo(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "test-1.0-1-x86_64.pkg.tar.zst")
			writeTestPackage(t, path, tt.members)

			got, err := Package(path).Pkgbase()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Pkgbase: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// buriedPkginfo puts .PKGINFO one member past where we stop looking.
func buriedPkginfo() []tarMember {
	members := make([]tarMember, 0, maxPkginfoMembers+1)
	for i := range maxPkginfoMembers {
		members = append(members, tarMember{Name: "usr/share/filler" + strconv.Itoa(i), Content: []byte("x")})
	}
	return append(members, tarMember{Name: pkginfoName, Content: pkginfo("foo", "foo")})
}

func TestPackagePkgbaseCorruptArchive(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "test-1.0-1-x86_64.pkg.tar.zst")
	if err := os.WriteFile(path, []byte("not a zstd stream"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Package(path).Pkgbase(); err == nil {
		t.Error("expected an error for a corrupt archive")
	}
}

func TestPackagePkgbaseMissingFile(t *testing.T) {
	t.Parallel()

	_, err := Package(filepath.Join(t.TempDir(), "absent-1.0-1-x86_64.pkg.tar.zst")).Pkgbase()
	if !os.IsNotExist(err) {
		t.Errorf("expected a not-exist error, got %v", err)
	}
}

func TestResolveByPkgbase(t *testing.T) {
	t.Parallel()

	stale := &ent.DBPackage{Pkgbase: testBaseRabbitmq, Packages: []string{testBaseRabbitmq, testPkgRabbitmqAdm}}
	owner := &ent.DBPackage{Pkgbase: testPkgRabbitmqAdm, Packages: []string{testPkgRabbitmqAdm}}

	tests := []struct {
		name       string
		candidates []*ent.DBPackage
		pkgbase    string
		want       *ent.DBPackage
		wantErr    bool
	}{
		{
			name:       "no candidates",
			candidates: nil,
			pkgbase:    testPkgRabbitmqAdm,
			wantErr:    true,
		},
		{
			name:       "single candidate matching",
			candidates: []*ent.DBPackage{owner},
			pkgbase:    testPkgRabbitmqAdm,
			want:       owner,
		},
		{
			// the production case: a stale row still claims the pkgname
			name:       "stale claimant alongside the owner",
			candidates: []*ent.DBPackage{stale, owner},
			pkgbase:    testPkgRabbitmqAdm,
			want:       owner,
		},
		{
			name:       "no candidate has the pkgbase",
			candidates: []*ent.DBPackage{stale, owner},
			pkgbase:    "something-else",
			wantErr:    true,
		},
		{
			// no unique constraint backs (pkgbase, march, repository), so this has
			// to error rather than pick: callers purge and delete on the result
			name: "two distinct rows share the pkgbase",
			candidates: []*ent.DBPackage{
				{Pkgbase: testPkgRabbitmqAdm, Packages: []string{testPkgRabbitmqAdm}},
				{Pkgbase: testPkgRabbitmqAdm, Packages: []string{testPkgRabbitmqAdm}},
			},
			pkgbase: testPkgRabbitmqAdm,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := resolveByPkgbase(tt.candidates, tt.pkgbase)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				if ent.IsNotFound(err) {
					t.Error("must not report as ent.IsNotFound: callers read that as an orphan and delete the build")
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveByPkgbase: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMoveDisposition(t *testing.T) {
	t.Parallel()

	// deliberately no os.IsNotExist case: that predicate belongs to
	// stateDisposition, and asserting it here would pin the conflation the two
	// classifiers exist to keep apart
	tests := []struct {
		name    string
		err     error
		isDebug bool
		want    disposition
	}{
		{name: "no error", err: nil, want: dispPublish},
		{name: "not found", err: &ent.NotFoundError{}, want: dispDelete},
		{name: "not singular", err: &ent.NotSingularError{}, want: dispResolve},
		{name: "unclassified", err: errors.New("connection refused"), want: dispKeep},
		{name: "debug wins over not found", err: &ent.NotFoundError{}, isDebug: true, want: dispDebug},
		{name: "debug wins over not singular", err: &ent.NotSingularError{}, isDebug: true, want: dispDebug},
		{name: "debug wins over unclassified", err: errors.New("boom"), isDebug: true, want: dispDebug},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := moveDisposition(tt.err, tt.isDebug); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStateDisposition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want disposition
	}{
		{
			name: "not exist",
			err:  &fs.PathError{Op: "open", Path: "state/foo", Err: syscall.ENOENT},
			want: dispDelete,
		},
		{
			name: "permission denied",
			err:  &fs.PathError{Op: "open", Path: "state/foo", Err: syscall.EACCES},
			want: dispKeep,
		},
		{
			name: "io error",
			err:  &fs.PathError{Op: "read", Path: "state/foo", Err: syscall.EIO},
			want: dispKeep,
		},
		{
			name: "unclassified",
			err:  errors.New("boom"),
			want: dispKeep,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := stateDisposition(tt.err); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWaitingMatches(t *testing.T) {
	t.Parallel()

	const artifact = "/w/to_be_moved/extra-x86-64-v3/rabbitmqadmin-1:2.32.0-1-x86_64.pkg.tar.zst"

	tests := []struct {
		name     string
		files    []string
		packages []string
		want     bool
	}{
		{
			name:     "artifact for one of the split packages",
			files:    []string{artifact},
			packages: []string{testPkgRabbitmqAdm},
			want:     true,
		},
		{
			name:     "only unrelated artifacts",
			files:    []string{"/w/to_be_moved/extra-x86-64-v3/gitea-1.27.1-1-x86_64.pkg.tar.zst"},
			packages: []string{testPkgRabbitmqAdm},
			want:     false,
		},
		{
			name:     "nothing waiting",
			files:    nil,
			packages: []string{testPkgRabbitmqAdm},
			want:     false,
		},
		{
			// a row that never completed a build has no package list, so nothing
			// can be attributed to it
			name:     "row has no packages",
			files:    []string{artifact},
			packages: nil,
			want:     false,
		},
		{
			name: "matches a later split package",
			files: []string{
				"/w/to_be_moved/extra-x86-64-v3/gitea-1.27.1-1-x86_64.pkg.tar.zst",
				artifact,
			},
			packages: []string{testBaseRabbitmq, testPkgRabbitmqAdm},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := waitingMatches(tt.files, tt.packages); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
