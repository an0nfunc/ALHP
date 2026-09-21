package main

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"net/http"
)

// labelRepository is the repo-march label every metric here is keyed by.
const labelRepository = "repository"

func (b *BuildManager) setupMetrics(port uint32) {
	b.metrics.queueSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "build_queue_size",
		Help: "Build queue size",
	}, []string{labelRepository, "status"})

	// counts builds ALHP terminated itself, so hangs show up as a rate instead of
	// needing someone to read the journal
	b.metrics.buildsKilled = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "build_killed_total",
		Help: "Builds killed for making no progress, going silent, or exceeding the build timeout",
	}, []string{labelRepository, "reason"})

	// built packages we could not publish and therefore kept rather than deleted.
	// Deleting them used to be silent; keeping them would be too. Labeled by cause,
	// because a pkgname no row can be attributed to and an unreadable state file
	// need different responses
	b.metrics.waitingUnmovable = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "waiting_unmovable_packages",
		Help: "Built packages left in the waiting dir because they could not be published",
	}, []string{labelRepository, "reason"})

	// pkgbases state.git still carries that no longer resolve upstream, usually
	// because the pkgname was re-homed under a different pkgbase
	b.metrics.staleStateFiles = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "stale_state_files",
		Help: "State files whose pkgbase cannot be resolved in the upstream repositories",
	}, []string{labelRepository})

	// packages we publish at a version above a conflicts/replaces bound upstream
	// wrote against them, which is an upgrade pacman silently declines to resolve
	b.metrics.defeatedBoundPackages = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "defeated_bound_packages",
		Help: "Published packages whose version is above an upstream conflicts/replaces bound written against them",
	}, []string{labelRepository})

	// conflicts/replaces bound entries observed that our build numbers defeat,
	// labeled by where we saw it. "artifact" is a built package that still carries
	// one; "purged" is the merge moment itself, caught as the package leaves the
	// Arch repos, which the gauge above cannot see because the row is deleted
	// in the same pass
	b.metrics.defeatedBoundEntries = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "defeated_bound_entries_total",
		Help: "Conflicts/replaces bound entries defeated by our build numbers, by where they were seen",
	}, []string{labelRepository, "source"})

	mux := http.NewServeMux()
	mux.Handle("/", promhttp.Handler())
	go func() {
		err := http.ListenAndServe(fmt.Sprintf(":%d", port), mux) //nolint:gosec
		if err != nil {
			log.Errorf("failed to start metrics server: %v", err)
		}
	}()
}
