package main

import (
	"github.com/Morganamilo/go-srcinfo"
	"os"
	"os/exec"
	"path/filepath"
	"somegit.dev/ALHP/ALHP.GO/ent"
	"strings"
	"testing"
)

// mozillaPrimary is the shape validpgpkeys takes: a primary fingerprint, with
// the signing subkey it carries named nowhere.
const mozillaPrimary = "14F26682D0916CDD81E37B6D61B7B526D98F0353"

const PkgbuildTest = `# Maintainer: Jan Alexander Steffens (heftig) <heftig@archlinux.org>

pkgname=gnome-todo
pkgver=41.0+r69+ga9a5b7cd
pkgrel=1
pkgdesc="Task manager for GNOME"
url="https://wiki.gnome.org/Apps/Todo"
arch=(x86_64)
license=(GPL)
depends=(evolution-data-server libpeas python gtk4 libportal-gtk4 libadwaita)
makedepends=(gobject-introspection appstream-glib git meson yelp-tools)
groups=(gnome-extra)
_commit=a9a5b7cdde0244331d2d49220f04018be60c018e  # master
source=("git+https://gitlab.gnome.org/GNOME/gnome-todo.git#commit=$_commit")
sha256sums=('SKIP')

pkgver() {
  cd $pkgname
  git describe --tags | sed 's/^GNOME_TODO_//;s/_/./g;s/[^-]*-g/r&/;s/-/+/g'

}

prepare() {
  cd $pkgname
}

build() {
  arch-meson $pkgname build
  meson compile -C build
}

check() (
  glib-compile-schemas "${GSETTINGS_SCHEMA_DIR:=$PWD/$pkgname/data}"
  export GSETTINGS_SCHEMA_DIR

  meson test -C build --print-errorlogs
)

package() {
  meson install -C build --destdir "$pkgdir"
}

# vim:set sw=2 et:
`

const PkgbuildTestWithPkgrelSub = `# Maintainer: Jan Alexander Steffens (heftig) <heftig@archlinux.org>

pkgname=gnome-todo
pkgver=41.0+r69+ga9a5b7cd
pkgrel=1.1
pkgdesc="Task manager for GNOME"
url="https://wiki.gnome.org/Apps/Todo"
arch=(x86_64)
license=(GPL)
depends=(evolution-data-server libpeas python gtk4 libportal-gtk4 libadwaita)
makedepends=(gobject-introspection appstream-glib git meson yelp-tools)
groups=(gnome-extra)
_commit=a9a5b7cdde0244331d2d49220f04018be60c018e  # master
source=("git+https://gitlab.gnome.org/GNOME/gnome-todo.git#commit=$_commit")
sha256sums=('SKIP')

pkgver() {
  cd $pkgname
  git describe --tags | sed 's/^GNOME_TODO_//;s/_/./g;s/[^-]*-g/r&/;s/-/+/g'

}

prepare() {
  cd $pkgname
}

build() {
  arch-meson $pkgname build
  meson compile -C build
}

check() (
  glib-compile-schemas "${GSETTINGS_SCHEMA_DIR:=$PWD/$pkgname/data}"
  export GSETTINGS_SCHEMA_DIR

  meson test -C build --print-errorlogs
)

package() {
  meson install -C build --destdir "$pkgdir"
}

# vim:set sw=2 et:
`

func TestCloneBranch(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		useLatest bool
		tagVer    string
		want      string
	}{
		{"state-tag-default", false, "3.3-4", "3.3-4"},
		{"main-when-drift", true, "3.3-4", "main"},
		{"main-ignores-empty-tag", true, "", "main"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := &ProtoPackage{
				UseLatest: tc.useLatest,
				State:     &StateInfo{TagVer: tc.tagVer},
			}
			if got := p.cloneBranch(); got != tc.want {
				t.Errorf("cloneBranch() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSkipReasonsDistinct(t *testing.T) { //nolint:paralleltest
	if SkipReasonAnyArch == SkipReasonAnyArchMoved {
		t.Fatal("any-arch skip reasons must remain distinguishable: callers and operators inspect skip_reason to tell why a package was dropped")
	}
}

func TestIncreasePkgRel(t *testing.T) { //nolint:paralleltest
	pkgbuild, err := os.CreateTemp(t.TempDir(), "")
	if err != nil {
		t.Fatal("unable to setup temp. PKGBUILD")
	}
	defer func(name string) {
		_ = os.Remove(name)
	}(pkgbuild.Name())

	_, err = pkgbuild.WriteString(PkgbuildTest)
	if err != nil {
		t.Fatal("unable to write to temp. PKGBUILD")
	}
	_ = pkgbuild.Close()

	buildPkg := &ProtoPackage{
		Pkgbase:  "gnome-todo",
		Pkgbuild: pkgbuild.Name(),
	}

	err = buildPkg.increasePkgRel(t.Context(), 1)
	if err != nil {
		t.Logf("increasePkgRel: %v", err)
		t.Fail()
	}

	versionSplit := strings.Split(buildPkg.Version, "-")
	if versionSplit[len(versionSplit)-1] != "1.1" {
		t.Logf("increasePkgRel: expected 1.1 pkgrel, got: %s", buildPkg.Version)
		t.Fail()
	}

	buildPkg.Srcinfo = nil
	err = buildPkg.genSrcinfo(t.Context())
	if err != nil {
		t.Logf("increasePkgRel: %v", err)
		t.Fail()
	}

	if buildPkg.Srcinfo.Pkgrel != "1.1" {
		t.Logf("increasePkgRel: expected 1.1 pkgrel, got: %s", buildPkg.Srcinfo.Pkgrel)
		t.Fail()
	}
}

func TestIncreasePkgRelWithPkgSub(t *testing.T) { //nolint:paralleltest
	pkgbuild, err := os.CreateTemp(t.TempDir(), "")
	if err != nil {
		t.Fatal("unable to setup temp. PKGBUILD")
	}
	defer func(name string) {
		_ = os.Remove(name)
	}(pkgbuild.Name())

	_, err = pkgbuild.WriteString(PkgbuildTestWithPkgrelSub)
	if err != nil {
		t.Fatal("unable to write to temp. PKGBUILD")
	}
	_ = pkgbuild.Close()

	buildPkg := &ProtoPackage{
		Pkgbase:  "gnome-todo",
		Pkgbuild: pkgbuild.Name(),
	}

	// upstream already owns 1.1, so the build number has to clear it; passing
	// one that does not is a caller bug and must not silently republish 1.1
	if err := buildPkg.increasePkgRel(t.Context(), 1); err == nil {
		t.Logf("increasePkgRel: expected build number 1 to be rejected against upstream pkgrel 1.1, got %s",
			buildPkg.Version)
		t.Fail()
	}

	err = buildPkg.increasePkgRel(t.Context(), 2)
	if err != nil {
		t.Logf("increasePkgRel: %v", err)
		t.Fail()
	}

	versionSplit := strings.Split(buildPkg.Version, "-")
	if versionSplit[len(versionSplit)-1] != "1.2" {
		t.Logf("increasePkgRel: expected 1.2 pkgrel, got: %s", buildPkg.Version)
		t.Fail()
	}

	buildPkg.Srcinfo = nil
	err = buildPkg.genSrcinfo(t.Context())
	if err != nil {
		t.Logf("increasePkgRel: %v", err)
		t.Fail()
	}

	if buildPkg.Srcinfo.Pkgrel != "1.2" {
		t.Logf("increasePkgRel: expected 1.2 pkgrel, got: %s", buildPkg.Srcinfo.Pkgrel)
		t.Fail()
	}
}

// Versions shared by the build-number tests, named to keep the tables readable.
const (
	verOldRel1 = "1.0-1"
	verOldRel2 = "1.0-2"
	verNewRel1 = "1.1-1"
	verNewRel2 = "1.1-2"
	// upstream carrying a build number of its own
	verOldRel1Sub1 = "1.0-1.1"
	verOldRel1Sub3 = "1.0-1.3"
	verOldRel1Sub2 = "1.0-1.2"
)

func TestNextBuildNo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		version        string
		upstreamPkgRel string
		maxVersionBase string
		buildNo        int
		wantBuildNo    int
		wantMaxVersion string
	}{
		{
			name:           "first build of a package",
			version:        verOldRel1,
			upstreamPkgRel: "1",
			wantBuildNo:    1,
			wantMaxVersion: verOldRel1,
		},
		{
			name:           "new upstream version restarts",
			version:        verNewRel1,
			upstreamPkgRel: "1",
			maxVersionBase: verOldRel1,
			buildNo:        3,
			wantBuildNo:    1,
			wantMaxVersion: verNewRel1,
		},
		{
			name:           "rebuild of the published version",
			version:        verOldRel1,
			upstreamPkgRel: "1",
			maxVersionBase: verOldRel1,
			buildNo:        1,
			wantBuildNo:    2,
			wantMaxVersion: verOldRel1,
		},
		{
			// the kpipewire case: a drift build from main published 1.0-2.1,
			// housekeeping purged it because upstream never released -2, the
			// rebuild went to -1, and upstream then released -2 for real
			name:           "upstream walking a version back",
			version:        verOldRel1,
			upstreamPkgRel: "1",
			maxVersionBase: verOldRel2,
			buildNo:        1,
			wantBuildNo:    2,
			wantMaxVersion: verOldRel2,
		},
		{
			name:           "returning to a version already published",
			version:        verOldRel2,
			upstreamPkgRel: "2",
			maxVersionBase: verOldRel2,
			buildNo:        2,
			wantBuildNo:    3,
			wantMaxVersion: verOldRel2,
		},
		{
			// the mark records the base, not the version: upstream 1 and
			// upstream 1.4 both publish into 1.N and share a namespace
			name:           "clears a build number upstream owns",
			version:        "1.0-1.4",
			upstreamPkgRel: "1.4",
			wantBuildNo:    5,
			wantMaxVersion: verOldRel1,
		},
		{
			name:           "upstream fractional bump does not restart",
			version:        "1.0-1.1",
			upstreamPkgRel: "1.1",
			maxVersionBase: verOldRel1,
			buildNo:        2,
			wantBuildNo:    3,
			wantMaxVersion: verOldRel1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := &ProtoPackage{
				Version:   tt.version,
				Srcinfo:   &srcinfo.Srcinfo{PackageBase: srcinfo.PackageBase{Pkgrel: tt.upstreamPkgRel}},
				DBPackage: &ent.DBPackage{MaxVersionBase: tt.maxVersionBase, BuildNo: tt.buildNo},
			}

			buildNo, maxVersionBase, err := p.nextBuildNo()
			if err != nil {
				t.Fatalf("nextBuildNo: %v", err)
			}
			if buildNo != tt.wantBuildNo {
				t.Errorf("nextBuildNo: expected build number %d, got %d", tt.wantBuildNo, buildNo)
			}
			if maxVersionBase != tt.wantMaxVersion {
				t.Errorf("nextBuildNo: expected max version %s, got %s", tt.wantMaxVersion, maxVersionBase)
			}
		})
	}
}

// Reuse is what breaks mirrors and pacman caches, so it is the property worth
// pinning rather than any individual number these histories happen to produce.
func TestNextBuildNoNeverReusesAFilename(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		// stands in for what seedBuildNo would have written, so a history
		// starting mid-life is covered too
		seed     ent.DBPackage
		versions []string
	}{
		{
			name:     "upstream walking back and forth",
			versions: []string{verOldRel1, verOldRel2, verOldRel1, verOldRel2, verNewRel1, verOldRel2, verNewRel1, verNewRel2},
		},
		{
			// upstream 1 and upstream 1.1 both publish into 1.N, so a
			// fractional bump must not be read as a new namespace
			name:     "upstream bumping its own pkgrel fraction",
			versions: []string{verOldRel1, verOldRel1, verOldRel1Sub1, verOldRel1Sub1, verOldRel1Sub2, verOldRel1},
		},
		{
			// a row purged before the counters existed: repo_version is gone,
			// last_version_build is what seedBuildNo has to read
			name:     "seeded from a prior life",
			seed:     seededRow("", verOldRel1Sub3),
			versions: []string{verOldRel1, verOldRel2, verOldRel1},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pkgbuild := filepath.Join(t.TempDir(), "PKGBUILD")
			dbPkg := tc.seed
			published := make(map[string]bool, len(tc.versions))

			for i, version := range tc.versions {
				upstreamPkgRel := pkgRel(version)
				if err := os.WriteFile(pkgbuild, []byte("pkgrel="+upstreamPkgRel+"\n"), 0o600); err != nil {
					t.Fatalf("unable to write temp. PKGBUILD: %v", err)
				}

				p := &ProtoPackage{
					Version:   version,
					Pkgbuild:  pkgbuild,
					Srcinfo:   &srcinfo.Srcinfo{PackageBase: srcinfo.PackageBase{Pkgrel: upstreamPkgRel}},
					DBPackage: &dbPkg,
				}

				buildNo, maxVersionBase, err := p.nextBuildNo()
				if err != nil {
					t.Fatalf("build %d of %s: nextBuildNo: %v", i, version, err)
				}
				dbPkg.BuildNo, dbPkg.MaxVersionBase = buildNo, maxVersionBase

				if err := p.increasePkgRel(t.Context(), buildNo); err != nil {
					t.Fatalf("build %d of %s: increasePkgRel: %v", i, version, err)
				}
				if published[p.Version] {
					t.Fatalf("build %d of %s republished %s", i, version, p.Version)
				}
				published[p.Version] = true
			}
		})
	}
}

// seededRow goes through the real seed helper so the histories below exercise
// the handoff into nextBuildNo rather than a hand-picked pair.
func seededRow(versions ...string) ent.DBPackage {
	base, buildNo := raiseBuildNo("", 0, versions...)
	return ent.DBPackage{MaxVersionBase: base, BuildNo: buildNo}
}

func TestRaiseBuildNo(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name           string
		base           string
		buildNo        int
		versions       []string
		wantMaxVersion string
		wantBuildNo    int
	}{
		{name: "nothing recorded", versions: []string{"", ""}},
		{name: "published version only", versions: []string{verOldRel1Sub3, ""}, wantMaxVersion: verOldRel1, wantBuildNo: 3},
		{
			// a purged row: repo_version is cleared, last_version_build is not
			name: "last build only", versions: []string{"", verOldRel1Sub2},
			wantMaxVersion: verOldRel1, wantBuildNo: 2,
		},
		{
			// the two dimensions peak in different versions, so taking either
			// version wholesale would walk the other one backwards. Both
			// orderings, since the caller's argument order is fixed
			name: "dimensions raised apart", versions: []string{"1.0-2.1", verOldRel1Sub3},
			wantMaxVersion: verOldRel2, wantBuildNo: 3,
		},
		{
			name: "dimensions raised apart, reversed", versions: []string{verOldRel1Sub3, "1.0-2.1"},
			wantMaxVersion: verOldRel2, wantBuildNo: 3,
		},
		{name: "unreadable version is skipped", versions: []string{"1.0-1.beta", verOldRel1Sub2}, wantMaxVersion: verOldRel1, wantBuildNo: 2},
		{name: "all unreadable", versions: []string{"1.0-1.beta"}},
		{
			// housekeeping reconciling a row against what is on disk: the row is
			// ahead in both dimensions, so nothing may move
			name: "row ahead of disk holds", base: verOldRel2, buildNo: 4, versions: []string{verOldRel1Sub2},
			wantMaxVersion: verOldRel2, wantBuildNo: 4,
		},
		{
			name: "disk ahead of row raises both", base: verOldRel1, buildNo: 1, versions: []string{"1.0-2.5"},
			wantMaxVersion: verOldRel2, wantBuildNo: 5,
		},
		{
			// the counter may not follow the base backwards
			name: "higher counter on a lower base", base: verOldRel2, buildNo: 1, versions: []string{"1.0-1.7"},
			wantMaxVersion: verOldRel2, wantBuildNo: 7,
		},
		{
			name: "unreadable disk version leaves the row alone", base: verOldRel1, buildNo: 2, versions: []string{"1.0-1.beta"},
			wantMaxVersion: verOldRel1, wantBuildNo: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			base, buildNo := raiseBuildNo(tc.base, tc.buildNo, tc.versions...)
			if base != tc.wantMaxVersion || buildNo != tc.wantBuildNo {
				t.Errorf("raiseBuildNo(%q, %d, %q) = %q, %d, want %q, %d", tc.base, tc.buildNo, tc.versions,
					base, buildNo, tc.wantMaxVersion, tc.wantBuildNo)
			}
		})
	}
}

// gpgStub puts a gpg on PATH that records every --recv-keys invocation and
// answers --list-keys as asked, so importKeys can be exercised without a keyring
// or a network. --recv-keys exits zero without importing, which is what a
// keyserver holding a key with no user IDs produces. Returns the path the calls
// are recorded to, which does not exist until one is made.
func gpgStub(t *testing.T, keysResolve bool) string {
	t.Helper()

	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")

	listExit := "1"
	if keysResolve {
		listExit = "0"
	}

	stub := "#!/bin/sh\nfor a in \"$@\"; do\n  case \"$a\" in\n" +
		"    --recv-keys) echo \"$@\" >> '" + calls + "'; exit 0 ;;\n" +
		"    --list-keys) exit " + listExit + " ;;\n  esac\ndone\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "gpg"), []byte(stub), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	return calls
}

// TestAbsentKeysReportsUnknown covers the check importKeys reports on. GNUPGHOME
// is redirected because gpg creates a keybox and a trustdb on first use, and the
// suite must not write into the keyring of whoever runs it.
func TestAbsentKeysReportsUnknown(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not available")
	}
	t.Setenv("GNUPGHOME", t.TempDir())

	// a syntactically valid long key id that no keyring can resolve
	const unknown = "0000000000000000"

	absent := absentKeys(t.Context(), []string{unknown})
	if len(absent) != 1 || absent[0] != unknown {
		t.Errorf("absentKeys(%q) = %v, want [%q]", unknown, absent, unknown)
	}

	if absent := absentKeys(t.Context(), nil); absent != nil {
		t.Errorf("absentKeys(nil) = %v, want nil", absent)
	}

	// validpgpkeys is upstream text, and gpg has no positional boundary: read as
	// an option this one exits zero and lists the whole keyring, which without the
	// end-of-options guard reads as a key that is present
	const optionShaped = "--with-colons"

	absent = absentKeys(t.Context(), []string{optionShaped})
	if len(absent) != 1 || absent[0] != optionShaped {
		t.Errorf("absentKeys(%q) = %v, want [%q]", optionShaped, absent, optionShaped)
	}
}

// TestImportKeysWithoutValidPGPKeys guards the common case: most packages declare
// none, and those must not reach a keyserver at all.
func TestImportKeysWithoutValidPGPKeys(t *testing.T) { //nolint:paralleltest
	calls := gpgStub(t, true)

	p := &ProtoPackage{Srcinfo: &srcinfo.Srcinfo{}}
	if err := p.importKeys(t.Context()); err != nil {
		t.Fatalf("importKeys() with no validpgpkeys = %v, want nil", err)
	}

	if recorded, err := os.ReadFile(calls); err == nil {
		t.Errorf("a package declaring no keys still queried a keyserver: %s", recorded)
	}
}

// TestImportKeysFetchesEvenWhenKeysResolve pins the property that makes a key
// rotation recoverable. validpgpkeys names primary fingerprints, so a primary
// imported by an earlier build resolves even when the signing subkey upstream
// moved to is absent. Fetching only the keys that fail to resolve therefore
// fetches nothing in exactly the case that needs it.
func TestImportKeysFetchesEvenWhenKeysResolve(t *testing.T) { //nolint:paralleltest
	calls := gpgStub(t, true)

	p := &ProtoPackage{Srcinfo: &srcinfo.Srcinfo{
		PackageBase: srcinfo.PackageBase{ValidPGPKeys: []string{mozillaPrimary}},
	}}
	if err := p.importKeys(t.Context()); err != nil {
		t.Fatalf("importKeys() = %v, want nil", err)
	}

	recorded, err := os.ReadFile(calls)
	if err != nil {
		t.Fatalf("no --recv-keys was attempted, so a rotated subkey would never arrive: %v", err)
	}
	if !strings.Contains(string(recorded), mozillaPrimary) {
		t.Errorf("--recv-keys did not ask for the declared key: %s", recorded)
	}

	// the fetch takes the same upstream text the probe does, so it needs the same
	// end-of-options guard: an option-shaped entry is otherwise read as an option,
	// and one gpg accepts makes the round exit zero having fetched nothing
	if !strings.Contains(string(recorded), "--recv-keys -- ") {
		t.Errorf("--recv-keys was not given an end-of-options marker: %s", recorded)
	}
}

// TestImportKeysTriesEveryKeyserver guards the other half of the same property.
// A zero exit does not mean the key arrived: a server holding it without user IDs
// skips the import and still exits zero. Stopping at the first such server leaves
// the key absent when a later one would have supplied it.
func TestImportKeysTriesEveryKeyserver(t *testing.T) { //nolint:paralleltest
	calls := gpgStub(t, false)

	p := &ProtoPackage{Srcinfo: &srcinfo.Srcinfo{
		PackageBase: srcinfo.PackageBase{ValidPGPKeys: []string{mozillaPrimary}},
	}}
	err := p.importKeys(t.Context())
	if err == nil {
		t.Fatal("importKeys() = nil, want an error naming the key still absent")
	}
	if !strings.Contains(err.Error(), mozillaPrimary) {
		t.Errorf("error does not name the absent key: %v", err)
	}

	recorded, readErr := os.ReadFile(calls)
	if readErr != nil {
		t.Fatalf("no keyserver was queried: %v", readErr)
	}
	for _, keyserver := range keyservers {
		if !strings.Contains(string(recorded), keyserver) {
			t.Errorf("keyserver %q was never queried although the key stayed absent:\n%s", keyserver, recorded)
		}
	}
}
