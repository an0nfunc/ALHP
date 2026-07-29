package main

import (
	"testing"

	"github.com/c2h5oh/datasize"
	"somegit.dev/ALHP/ALHP.GO/ent"
)

const (
	testPkgbase = "foo"
	testMarchV2 = "x86-64-v2"
	testMarchV3 = "x86-64-v3"
)

// pkg builds a queue candidate. maxRSS mirrors DBPackage.MaxRss, as buildQueue does
// when it admits a package.
func pkg(pkgbase, march, repo string, maxRSS *int64) *ProtoPackage {
	return &ProtoPackage{
		Pkgbase:   pkgbase,
		March:     march,
		FullRepo:  repo + "-" + march,
		DBPackage: &ent.DBPackage{MaxRss: maxRSS},
		maxRSS:    maxRSS,
	}
}

func TestBuildingBlocks(t *testing.T) {
	t.Parallel()

	profiled := new(int64(1024))

	tests := []struct {
		name      string
		building  []*ProtoPackage
		candidate *ProtoPackage
		want      bool
	}{
		{
			name:      "nothing building",
			building:  nil,
			candidate: pkg(testPkgbase, testMarchV3, "extra", profiled),
			want:      false,
		},
		{
			name:      "unrelated pkgbase runs in parallel",
			building:  []*ProtoPackage{pkg("bar", testMarchV3, "extra", profiled)},
			candidate: pkg(testPkgbase, testMarchV3, "extra", profiled),
			want:      false,
		},
		{
			name:      "same pkgbase same march blocked",
			building:  []*ProtoPackage{pkg(testPkgbase, testMarchV3, "extra", profiled)},
			candidate: pkg(testPkgbase, testMarchV3, "extra", profiled),
			want:      true,
		},
		{
			// they share build/<march>/<pkgbase>-<version>, the PKGBUILD
			// increasePkgRel rewrites, and logs/<march>/<pkgbase>.log, none of
			// which are repo-keyed. reachable during a core/extra repo move.
			name:      "same pkgbase same march different repo blocked",
			building:  []*ProtoPackage{pkg(testPkgbase, testMarchV3, "core", profiled)},
			candidate: pkg(testPkgbase, testMarchV3, "extra", profiled),
			want:      true,
		},
		{
			name:      "different march both profiled runs in parallel",
			building:  []*ProtoPackage{pkg(testPkgbase, testMarchV2, "extra", profiled)},
			candidate: pkg(testPkgbase, testMarchV3, "extra", profiled),
			want:      false,
		},
		{
			name:      "different march candidate unprofiled blocked",
			building:  []*ProtoPackage{pkg(testPkgbase, testMarchV2, "extra", profiled)},
			candidate: pkg(testPkgbase, testMarchV3, "extra", nil),
			want:      true,
		},
		{
			// MaxRss is per (pkgbase, march, repository), so a pair can be
			// profiled on one march and not the other
			name:      "different march building side unprofiled blocked",
			building:  []*ProtoPackage{pkg(testPkgbase, testMarchV2, "extra", nil)},
			candidate: pkg(testPkgbase, testMarchV3, "extra", profiled),
			want:      true,
		},
		{
			name:      "different march both unprofiled blocked",
			building:  []*ProtoPackage{pkg(testPkgbase, testMarchV2, "extra", nil)},
			candidate: pkg(testPkgbase, testMarchV3, "extra", nil),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := buildingBlocks(tt.building, tt.candidate); got != tt.want {
				t.Errorf("buildingBlocks() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestBuildingBlocksIgnoresOrder is the case the two-pass structure exists for. The
// candidate is itself already building, with a same-pkgbase different-march entry
// ahead of it in the slice. A single loop with || short-circuiting would reach the
// candidate's DBPackage on the first entry, racing the build goroutine that
// reassigns it; the first pass must catch the candidate before any DBPackage read.
func TestBuildingBlocksIgnoresOrder(t *testing.T) {
	t.Parallel()

	profiled := new(int64(1024))
	candidate := pkg(testPkgbase, testMarchV3, "extra", profiled)
	sibling := pkg(testPkgbase, testMarchV2, "extra", profiled)

	// sibling first, candidate second: the ordering that makes a merged loop wrong
	if !buildingBlocks([]*ProtoPackage{sibling, candidate}, candidate) {
		t.Error("a package already building must block itself regardless of slice order")
	}
	if !buildingBlocks([]*ProtoPackage{candidate, sibling}, candidate) {
		t.Error("a package already building must block itself")
	}
}

// TestSchedulerReadsDoNotTouchDBPackage is the demonstration of the race fix that
// `go test -race` cannot give on its own: no test drives buildQueue, so the
// detector never sees the scheduler read DBPackage.MaxRss concurrently with
// build() reassigning DBPackage. Instead of reproducing the race, this pins the
// property that removes it, that the reads taken while a package is in
// b.building go to the maxRSS snapshot and never to DBPackage. A nil DBPackage
// panics if either reader regresses.
func TestSchedulerReadsDoNotTouchDBPackage(t *testing.T) {
	t.Parallel()

	building := []*ProtoPackage{
		{Pkgbase: testPkgbase, March: testMarchV2, maxRSS: new(int64(1024))},
		{Pkgbase: "bar", March: testMarchV3, maxRSS: new(int64(2048))},
	}

	if got := pkgList2MaxMem(building); got != 3072*datasize.KB {
		t.Errorf("pkgList2MaxMem() = %v, want %v", got, 3072*datasize.KB)
	}

	// Same march, so the first pass returns before any DBPackage read. Guards the
	// promise that the first pass touches no DBPackage: if it did, this panics.
	sameMarch := &ProtoPackage{Pkgbase: testPkgbase, March: testMarchV2}
	if !buildingBlocks(building, sameMarch) {
		t.Error("same pkgbase and march must block without consulting DBPackage")
	}

	// Different march, so the first pass falls through and the second pass has to
	// read the in-flight package's recorded peak. That read must go to the maxRSS
	// snapshot: a regression to b.DBPackage.MaxRss nil-panics here, which is the
	// building-side half of the race and is otherwise untested.
	unprofiled := &ProtoPackage{Pkgbase: testPkgbase, March: testMarchV3}
	candidate := &ProtoPackage{
		Pkgbase:   testPkgbase,
		March:     testMarchV2,
		DBPackage: &ent.DBPackage{MaxRss: new(int64(1024))},
	}
	if !buildingBlocks([]*ProtoPackage{unprofiled}, candidate) {
		t.Error("an unprofiled in-flight build must block a same-pkgbase candidate on another march")
	}
}
