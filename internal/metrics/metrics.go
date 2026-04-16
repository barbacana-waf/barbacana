// Package metrics owns the Prometheus metric definitions for the WAF.
// All metrics register on the default Prometheus registry so Caddy's
// metrics handler exposes them alongside Go process metrics.
package metrics

import (
	"net/http"
	"runtime"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/barbacana-waf/barbacana/internal/version"
)

var (
	buildInfo *prometheus.GaugeVec

	// RequestsTotal counts all requests processed per route and action.
	RequestsTotal *prometheus.CounterVec

	// RequestsBlockedTotal counts blocked requests per route and protection
	// (sub-protection level label).
	RequestsBlockedTotal *prometheus.CounterVec

	once sync.Once
)

// Init registers all metrics. Idempotent.
func Init() {
	once.Do(func() {
		buildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "waf_build_info",
			Help: "Build-time metadata for the running barbacana binary. Always 1.",
		}, []string{"version", "go_version", "crs_version"})
		buildInfo.WithLabelValues(version.Version, runtime.Version(), version.CRSVersion).Set(1)

		RequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_requests_total",
			Help: "Total requests processed by the WAF.",
		}, []string{"route", "action"})

		RequestsBlockedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_requests_blocked_total",
			Help: "Requests blocked or detected, labeled by sub-protection.",
		}, []string{"route", "protection"})
	})
}

// Handler returns an http.Handler that serves the default Prometheus
// registry at /metrics, using OpenMetrics negotiation.
func Handler() http.Handler {
	return promhttp.Handler()
}
