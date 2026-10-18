package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func newTestCycleTracker() (*cycleTracker, *prometheus.GaugeVec) {
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "build_cycle_phase", Help: "test"}, []string{"phase"})
	return newCycleTracker(gauge), gauge
}

// activePhases returns the phases whose series is at 1, failing on any other value.
func activePhases(t *testing.T, gauge *prometheus.GaugeVec) []cyclePhase {
	t.Helper()
	if n := testutil.CollectAndCount(gauge); n != len(cyclePhases) {
		t.Fatalf("gauge has %d series, want one per phase (%d)", n, len(cyclePhases))
	}
	var active []cyclePhase
	for _, phase := range cyclePhases {
		switch v := testutil.ToFloat64(gauge.WithLabelValues(string(phase))); v {
		case 1:
			active = append(active, phase)
		case 0:
		default:
			t.Fatalf("phase %s has value %v", phase, v)
		}
	}
	return active
}

func TestCycleTrackerOnePhaseActive(t *testing.T) {
	t.Parallel()
	tracker, gauge := newTestCycleTracker()
	if got := activePhases(t, gauge); !slices.Equal(got, []cyclePhase{phaseStarting}) {
		t.Fatalf("after construction active phases are %v, want [starting]", got)
	}

	for _, phase := range []cyclePhase{phaseHousekeeping, phaseUpdatingChroot, phaseGeneratingQueue, phaseBuilding, phasePublishing} {
		tracker.enter(phase)
		if got := activePhases(t, gauge); !slices.Equal(got, []cyclePhase{phase}) {
			t.Fatalf("after entering %s active phases are %v", phase, got)
		}
	}
	tracker.waitUntil(time.Now().Add(time.Minute))
	if got := activePhases(t, gauge); !slices.Equal(got, []cyclePhase{phaseWaiting}) {
		t.Fatalf("after waitUntil active phases are %v", got)
	}
	tracker.enter(phaseHousekeeping)
	if got := activePhases(t, gauge); !slices.Equal(got, []cyclePhase{phaseHousekeeping}) {
		t.Fatalf("after the next cycle starts active phases are %v", got)
	}
}

func TestCycleTrackerEnterClearsState(t *testing.T) {
	t.Parallel()
	tracker, _ := newTestCycleTracker()

	tracker.enter(phaseGeneratingQueue)
	tracker.progress(3, 10)
	if s := tracker.snapshot(); s.Progress == nil || *s.Progress != (cycleProgress{Done: 3, Total: 10}) {
		t.Fatalf("progress = %+v, want 3/10", s.Progress)
	}

	tracker.waitUntil(time.Unix(2000, 0))
	s := tracker.snapshot()
	if s.Progress != nil {
		t.Fatalf("waiting still carries progress %+v", s.Progress)
	}
	if s.NextCycle != 2000 {
		t.Fatalf("next_cycle = %d, want 2000", s.NextCycle)
	}

	tracker.enter(phaseHousekeeping)
	if s := tracker.snapshot(); s.Progress != nil || s.NextCycle != 0 {
		t.Fatalf("housekeeping still carries progress %+v or next_cycle %d", s.Progress, s.NextCycle)
	}
}

func TestCycleSnapshotJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		snap cycleSnapshot
		want string
	}{
		{
			name: "generating queue",
			snap: cycleSnapshot{Phase: phaseGeneratingQueue, Since: 100, Progress: &cycleProgress{Done: 1200, Total: 5600}},
			want: `{"phase":"generating_queue","since":100,"progress":{"done":1200,"total":5600}}`,
		},
		{
			name: "waiting",
			snap: cycleSnapshot{Phase: phaseWaiting, Since: 100, NextCycle: 400},
			want: `{"phase":"waiting","since":100,"next_cycle":400}`,
		},
		{
			name: "plain phase",
			snap: cycleSnapshot{Phase: phaseHousekeeping, Since: 100},
			want: `{"phase":"housekeeping","since":100}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := json.Marshal(tt.snap)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestCycleTrackerServeHTTP(t *testing.T) {
	t.Parallel()
	tracker, _ := newTestCycleTracker()
	before := time.Now().Unix()
	tracker.enter(phaseGeneratingQueue)
	tracker.progress(1, 2)

	rec := httptest.NewRecorder()
	tracker.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/cycle", http.NoBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
	var got cycleSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Phase != phaseGeneratingQueue || got.Since < before || got.Progress == nil || got.Progress.Total != 2 {
		t.Fatalf("got %+v", got)
	}
}

func TestCycleTrackerConcurrentReads(t *testing.T) {
	t.Parallel()
	tracker, _ := newTestCycleTracker()
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 1000 {
			if i%100 == 0 {
				tracker.enter(phaseGeneratingQueue)
			}
			tracker.progress(i, 1000)
		}
	})
	wg.Go(func() {
		for range 1000 {
			tracker.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/cycle", http.NoBody))
		}
	})
	wg.Wait()
}

func TestStateFilesIn(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, name := range []string{
		"core-x86_64/zlib",
		"extra-x86_64/linux-zen",
		".git/objects/ab/cdef",
		".git/HEAD",
		"README.md",
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "empty-x86_64"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := stateFilesIn(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(dir, "core-x86_64/zlib"), filepath.Join(dir, "extra-x86_64/linux-zen")}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
