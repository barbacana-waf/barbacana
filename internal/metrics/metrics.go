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
	// (sub-protection level label). Bumped only in blocking mode, once per
	// blocked request, labelled by the protection that halted the pipeline.
	RequestsBlockedTotal *prometheus.CounterVec

	// DetectedThreatsTotal counts threats observed per route and protection,
	// regardless of mode.
	//   - In detect-only mode the pipeline traverses every stage and credits
	//     one increment per matched protection — a request that triggers
	//     three protections bumps three different label values.
	//   - In blocking mode the pipeline halts at the first blocking
	//     decision, so most blocked requests credit exactly one protection.
	//     The exception is CRS: one Coraza Evaluate call can return several
	//     matched rules (non-blocking sub-threshold matches plus the one
	//     that tips the anomaly score over the threshold), all of which
	//     are recorded before the halt.
	// Counts threats, not requests; for a per-request count use
	// RequestsTotal{action="blocked"|"detected"}.
	DetectedThreatsTotal *prometheus.CounterVec

	// AnomalyScoreHistogram records the CRS anomaly score per route.
	AnomalyScoreHistogram *prometheus.HistogramVec

	// OpenAPIValidationTotal counts OpenAPI validation results per route.
	OpenAPIValidationTotal *prometheus.CounterVec

	// RequestDurationOverhead records the WAF processing overhead per route.
	RequestDurationOverhead *prometheus.HistogramVec

	// HeadersInjectedTotal counts security headers injected per route and header.
	HeadersInjectedTotal *prometheus.CounterVec

	// EvaluationTimeoutTotal counts CRS evaluation timeouts per route.
	EvaluationTimeoutTotal *prometheus.CounterVec

	// BodySpooledTotal counts requests where the body was spooled to disk.
	BodySpooledTotal *prometheus.CounterVec

	// DecompressionRejectedTotal counts requests rejected for decompression ratio.
	DecompressionRejectedTotal *prometheus.CounterVec

	// ConfigReloadTotal counts config reload attempts by result.
	ConfigReloadTotal *prometheus.CounterVec

	// ConfigReloadTimestamp records the timestamp of the last successful reload.
	ConfigReloadTimestamp prometheus.Gauge

	// CRSRulesLoadedTotal records the number of CRS rules loaded.
	CRSRulesLoadedTotal prometheus.Gauge

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
			Help: "Requests blocked in blocking mode, labeled by the sub-protection that halted the pipeline. Detect-only matches are counted by waf_detected_threats_total.",
		}, []string{"route", "protection"})

		DetectedThreatsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_detected_threats_total",
			Help: "Threats observed across all modes, labeled by sub-protection. A single request may bump this counter multiple times when it matches multiple protections.",
		}, []string{"route", "protection"})

		AnomalyScoreHistogram = promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "waf_anomaly_score_histogram",
			Help:    "Distribution of CRS anomaly scores per route.",
			Buckets: []float64{1, 2, 3, 5, 10, 15, 25, 50},
		}, []string{"route"})

		OpenAPIValidationTotal = promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_openapi_validation_total",
			Help: "OpenAPI validation results per route.",
		}, []string{"route", "result"})

		RequestDurationOverhead = promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "waf_request_duration_overhead_seconds",
			Help:    "WAF processing overhead in seconds per route.",
			Buckets: prometheus.DefBuckets,
		}, []string{"route"})

		HeadersInjectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_security_headers_injected_total",
			Help: "Security headers injected per route and header.",
		}, []string{"route", "header"})

		EvaluationTimeoutTotal = promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_evaluation_timeout_total",
			Help: "CRS evaluation timeouts per route.",
		}, []string{"route"})

		BodySpooledTotal = promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_body_spooled_total",
			Help: "Requests where body was spooled to disk.",
		}, []string{"route"})

		DecompressionRejectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_decompression_rejected_total",
			Help: "Requests rejected for exceeding decompression ratio limit.",
		}, []string{"route"})

		ConfigReloadTotal = promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_config_reload_total",
			Help: "Config reload attempts by result (success/error).",
		}, []string{"result"})

		ConfigReloadTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
			Name: "waf_config_reload_timestamp_seconds",
			Help: "Unix timestamp of the last successful config reload.",
		})

		CRSRulesLoadedTotal = promauto.NewGauge(prometheus.GaugeOpts{
			Name: "waf_crs_rules_loaded_total",
			Help: "Number of CRS rules loaded.",
		})
	})
}

// Handler returns an http.Handler that serves the default Prometheus
// registry at /metrics, using OpenMetrics negotiation.
func Handler() http.Handler {
	return promhttp.Handler()
}
