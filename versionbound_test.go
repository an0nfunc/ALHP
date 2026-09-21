package main

import (
	"testing"

	"github.com/Jguer/go-alpm/v2"
)

// The merger that produced this check: geocode-glib-2 and geocode-glib-common
// were folded into geocode-glib, which carries the transition as
// `replaces=('geocode-glib-2<=3.26.4-5')` plus conflicts on the same bound.
const (
	mergedPkg      = "geocode-glib-2"
	mergedBound    = "3.26.4-5"
	mergedOurs     = "3.26.4-5.1"
	mergedReplacer = "geocode-glib"
)

func TestBoundFrom(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		dep  alpm.Depend
		want bool
	}{
		{"upper bound", alpm.Depend{Name: mergedPkg, Version: mergedBound, Mod: alpm.DepModLE}, true},
		{"strict upper bound", alpm.Depend{Name: mergedPkg, Version: mergedBound, Mod: alpm.DepModLT}, true},
		{"exact", alpm.Depend{Name: mergedPkg, Version: mergedBound, Mod: alpm.DepModEq}, true},
		// a bump only raises a version, so anything upstream satisfies with a
		// lower bound stays satisfied with our build number on top
		{"lower bound", alpm.Depend{Name: mergedPkg, Version: mergedBound, Mod: alpm.DepModGE}, false},
		{"strict lower bound", alpm.Depend{Name: mergedPkg, Version: mergedBound, Mod: alpm.DepModGT}, false},
		{"unversioned", alpm.Depend{Name: mergedPkg, Mod: alpm.DepModAny}, false},
		// pacman writes DepModAny for these, but an entry carrying a mod without
		// a version has nothing to compare and must not reach the index
		{"upper bound without version", alpm.Depend{Name: mergedPkg, Mod: alpm.DepModLE}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			bound, ok := boundFrom(mergedReplacer, "conflicts", tc.dep)
			if ok != tc.want {
				t.Fatalf("boundFrom(%v) ok = %t, want %t", tc.dep, ok, tc.want)
			}
			if !ok {
				return
			}
			if bound.source != mergedReplacer || bound.kind != "conflicts" ||
				bound.mod != tc.dep.Mod || bound.version != tc.dep.Version {
				t.Errorf("boundFrom(%v) = %+v, does not carry the entry through", tc.dep, bound)
			}
		})
	}
}

func TestSatisfiesBound(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		version string
		mod     alpm.DepMod
		bound   string
		want    bool
	}{
		{"at the bound", mergedBound, alpm.DepModLE, mergedBound, true},
		{"below the bound", "3.26.4-4", alpm.DepModLE, mergedBound, true},
		// the bug: our build number puts the installed package above a bound
		// written for the version it was built from
		{"our build number clears it", mergedOurs, alpm.DepModLE, mergedBound, false},
		{"strict at the bound", mergedBound, alpm.DepModLT, mergedBound, false},
		{"exact match", mergedBound, alpm.DepModEq, mergedBound, true},
		{"exact against our build number", mergedOurs, alpm.DepModEq, mergedBound, false},
		{"lower bound met", mergedOurs, alpm.DepModGE, mergedBound, true},
		{"lower bound unmet", "3.26.4-4", alpm.DepModGT, mergedBound, false},
		{"unversioned always holds", mergedOurs, alpm.DepModAny, "", true},
		// pacman compares only as far as the bound reaches, so a bound written
		// without a pkgrel cannot see our build number
		{"bound without pkgrel", mergedOurs, alpm.DepModLE, "3.26.4", true},
		{"epoch outranks pkgver", "1:1.0-1", alpm.DepModLE, "2.0-1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := satisfiesBound(tc.version, tc.mod, tc.bound); got != tc.want {
				t.Errorf("satisfiesBound(%q, %v, %q) = %t, want %t", tc.version, tc.mod, tc.bound, got, tc.want)
			}
		})
	}
}

func TestBoundIndexViolatedBy(t *testing.T) {
	t.Parallel()

	replaces := versionBound{source: mergedReplacer, kind: "replaces", mod: alpm.DepModLE, version: mergedBound}
	conflicts := versionBound{source: mergedReplacer, kind: "conflicts", mod: alpm.DepModLE, version: mergedBound}
	// an entry upstream's own version already violates, left in the repos from a
	// rename long past
	stale := versionBound{source: "unrelated", kind: "replaces", mod: alpm.DepModLE, version: "1.0-1"}

	for _, tc := range []struct {
		name    string
		index   boundIndex
		pkgname string
		version string
		want    int
	}{
		{
			"both entries of a merger", boundIndex{mergedPkg: {replaces, conflicts}},
			mergedPkg, mergedOurs, 2,
		},
		{
			"nothing constrains this package", boundIndex{mergedPkg: {replaces}},
			"unrelated-pkg", mergedOurs, 0,
		},
		{
			// upstream's own version is above the bound too, so the entry is not
			// ours to report and would otherwise never stop being logged
			"upstream already violates it", boundIndex{mergedPkg: {stale}},
			mergedPkg, mergedOurs, 0,
		},
		{
			// the version we would publish if we did not bump: nothing appended,
			// nothing we can be responsible for
			"no build number appended", boundIndex{mergedPkg: {replaces}},
			mergedPkg, mergedBound, 0,
		},
		{
			"still under the bound with our build number", boundIndex{mergedPkg: {replaces}},
			mergedPkg, "3.26.4-4.1", 0,
		},
		{
			// upstream moved past the bound on its own, so our build of it is
			// above the bound for a reason that is not the build number
			"upstream moved past the bound", boundIndex{mergedPkg: {replaces}},
			mergedPkg, "3.26.4-6.1", 0,
		},
		{"empty index", boundIndex{}, mergedPkg, mergedOurs, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := tc.index.violatedBy(tc.pkgname, tc.version)
			if len(got) != tc.want {
				t.Errorf("violatedBy(%q, %q) returned %d entries (%v), want %d",
					tc.pkgname, tc.version, len(got), got, tc.want)
			}
		})
	}
}

func TestVersionBoundString(t *testing.T) {
	t.Parallel()

	bound := versionBound{source: mergedReplacer, kind: "replaces", mod: alpm.DepModLE, version: mergedBound}
	want := "replaces <=3.26.4-5 (geocode-glib)"
	if got := bound.String(); got != want {
		t.Errorf("versionBound.String() = %q, want %q", got, want)
	}
}
