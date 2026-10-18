package main

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

// cyclePhase is the step of the build cycle syncWorker is in. Queue size alone
// cannot tell queue generation, housekeeping or the wait between cycles apart
// from a stalled builder, so the phase is reported next to it.
type cyclePhase string

const (
	phaseStarting        cyclePhase = "starting"
	phaseHousekeeping    cyclePhase = "housekeeping"
	phaseUpdatingChroot  cyclePhase = "updating_chroot"
	phaseGeneratingQueue cyclePhase = "generating_queue"
	phaseBuilding        cyclePhase = "building"
	phasePublishing      cyclePhase = "publishing"
	phaseWaiting         cyclePhase = "waiting"
)

var cyclePhases = []cyclePhase{
	phaseStarting, phaseHousekeeping, phaseUpdatingChroot, phaseGeneratingQueue,
	phaseBuilding, phasePublishing, phaseWaiting,
}

type cycleProgress struct {
	Done  int `json:"done"`
	Total int `json:"total"`
}

// cycleSnapshot is the /cycle response, which alhp-web passes on to the status page.
type cycleSnapshot struct {
	Phase     cyclePhase     `json:"phase"`
	Since     int64          `json:"since"`
	Progress  *cycleProgress `json:"progress,omitempty"`
	NextCycle int64          `json:"next_cycle,omitempty"`
}

// cycleTracker holds the current phase for /cycle and the build_cycle_phase
// gauge. Phases only change on the syncWorker goroutine; the lock is for the
// metrics server reading them.
type cycleTracker struct {
	mu    sync.Mutex
	gauge *prometheus.GaugeVec
	phase cyclePhase
	since time.Time
	prog  *cycleProgress
	next  time.Time
}

// newCycleTracker creates every phase's series up front, so each one exists from
// the first scrape instead of appearing the first time its phase is entered.
func newCycleTracker(gauge *prometheus.GaugeVec) *cycleTracker {
	for _, phase := range cyclePhases {
		gauge.WithLabelValues(string(phase)).Set(0)
	}
	t := &cycleTracker{gauge: gauge}
	t.enter(phaseStarting)
	return t
}

func (t *cycleTracker) enter(phase cyclePhase) {
	t.set(phase, time.Time{})
}

// waitUntil enters the wait between cycles, which ends at next.
func (t *cycleTracker) waitUntil(next time.Time) {
	t.set(phaseWaiting, next)
}

func (t *cycleTracker) set(phase cyclePhase, next time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.phase != "" {
		t.gauge.WithLabelValues(string(t.phase)).Set(0)
	}
	t.gauge.WithLabelValues(string(phase)).Set(1)
	t.phase, t.since, t.prog, t.next = phase, time.Now(), nil, next
}

func (t *cycleTracker) progress(done, total int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prog = &cycleProgress{Done: done, Total: total}
}

func (t *cycleTracker) snapshot() cycleSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := cycleSnapshot{Phase: t.phase, Since: t.since.Unix()}
	if t.prog != nil {
		prog := *t.prog
		s.Progress = &prog
	}
	if !t.next.IsZero() {
		s.NextCycle = t.next.Unix()
	}
	return s
}

func (t *cycleTracker) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(t.snapshot()); err != nil {
		log.Debugf("error writing cycle phase: %v", err)
	}
}
