package main

import "testing"

// Versions are named after the case that produced this pair of helpers: upstream
// tagged obs-studio 32.2.1-4 as an mbedtls3 rebuild for staging while extra kept
// 32.2.1-3, and building from main published a package whose dependency no
// released repo carried.
const (
	// verReleased is what upstream published; verStaged is the tag sitting on
	// main for a repo upstream has not promoted yet.
	verReleased = "32.2.1-3"
	verStaged   = "32.2.1-4"
	// verStateStale is a version state.git still records after upstream moved
	// on to verSyncAhead.
	verStateStale = "3.6.5-1"
	verSyncAhead  = "3.6.7-1"
)

func TestDriftToMain(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		syncVer  string
		stateVer string
		repoVer  string
		want     bool
	}{
		// state.git is current: main may hold tags upstream has not released,
		// so the pinned tag is the only safe ref.
		{"state-current-never-built", verReleased, verReleased, "", false},
		{"state-current-ordinary-update", verReleased, verReleased, "32.1.2-7.1", false},
		// state.git lags what upstream published: main is where the truth is.
		{"state-stale-never-built", verSyncAhead, verStateStale, "", true},
		{"state-stale-behind-upstream", verSyncAhead, verStateStale, "3.6.5-1.1", true},
		// state.git still stale, but we already published what upstream has:
		// nothing left to chase, and rebuilding every cycle is the loop that
		// comparing against repoVer alone was meant to stop.
		{"state-stale-caught-up", verSyncAhead, verStateStale, "3.6.7-1.1", false},
		{"state-stale-ahead-of-upstream", verSyncAhead, verStateStale, "3.6.7-2.1", false},
		// we built from the pinned tag before the mirror synced.
		{"mirror-behind-state", "32.2.1-2", verReleased, "32.2.1-3.1", false},
		{"epoch-beats-pkgver", "1:1.0-1", "9.0-1", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := driftToMain(tc.syncVer, tc.stateVer, tc.repoVer); got != tc.want {
				t.Errorf("driftToMain(%q, %q, %q) = %v, want %v",
					tc.syncVer, tc.stateVer, tc.repoVer, got, tc.want)
			}
		})
	}
}

func TestAheadOfUpstream(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		ver      string
		stateVer string
		syncVer  string
		want     bool
	}{
		// main carried a tag staged but never released: no repo has it.
		{"staged-tag", verStaged, verReleased, verReleased, true},
		// legitimate drift rebuild: state.git lags, the mirror does carry it.
		{"drift-rebuild-matches-mirror", verSyncAhead, verStateStale, verSyncAhead, false},
		// built from the pinned tag before the mirror synced.
		{"ahead-of-mirror-only", verReleased, verReleased, "32.2.1-2", false},
		{"in-step", verReleased, verReleased, verReleased, false},
		{"behind-both", "32.1.2-7", verReleased, verReleased, false},
		{"epoch-beats-pkgver", "1:1.0-1", "9.0-1", "9.0-1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := aheadOfUpstream(tc.ver, tc.stateVer, tc.syncVer); got != tc.want {
				t.Errorf("aheadOfUpstream(%q, %q, %q) = %v, want %v",
					tc.ver, tc.stateVer, tc.syncVer, got, tc.want)
			}
		})
	}
}
