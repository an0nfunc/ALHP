package main

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"net/http"
)

func (b *BuildManager) setupMetrics(port uint32) {
	b.metrics.queueSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "build_queue_size",
		Help: "Build queue size",
	}, []string{"repository", "status"})

	mux := http.NewServeMux()
	mux.Handle("/", promhttp.Handler())
	go func() {
		err := http.ListenAndServe(fmt.Sprintf(":%d", port), mux) //nolint:gosec
		if err != nil {
			log.Errorf("failed to start metrics server: %v", err)
		}
	}()
}
