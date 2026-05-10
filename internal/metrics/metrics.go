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
	dto "github.com/prometheus/client_model/go"

	"github.com/barbacana-waf/barbacana/internal/version"
)

var (
	buildInfo *prometheus.GaugeVec

	// RequestsTotal counts all requests processed per route and action.
	// The action label takes one of three values:
	//   - "allowed":  passed the pipeline cleanly and reached the upstream
	//   - "detected": matched at least one protection but was not blocked
	//                 (detect-only mode, or matches under the threshold)
	//   - "blocked":  blocking mode, halted by a protection
	// Sum across actions equals total requests handled.
	RequestsTotal *prometheus.CounterVec

	// RequestsInFlight is the gauge of requests currently in the
	// pipeline. Bumped at ServeHTTP entry, decremented via defer so
	// panic recovery still releases it. Use for capacity panels and
	// for detecting stuck pipelines (in-flight high while RequestsTotal
	// rate flat).
	RequestsInFlight prometheus.Gauge

	// UpstreamErrorsTotal counts proxy-side failures per route and
	// failure kind. Exists so dashboards can answer "WAF blocked vs
	// upstream broken" cleanly — Caddy's request counter at code=5xx
	// conflates upstream 5xx with the WAF's own block responses.
	// kind is one of:
	//   - "timeout":            context deadline or net.Error.Timeout()
	//   - "connection_refused": dial refused by upstream
	//   - "5xx":                upstream returned status >=500
	//   - "other":              any other proxy error
	UpstreamErrorsTotal *prometheus.CounterVec

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

	// RequestDurationOverhead records the WAF-only processing overhead
	// per route — total request handling time minus the upstream
	// round-trip. For requests blocked before the proxy hop, the upstream
	// time is zero and the metric reduces to pure pre-proxy WAF time.
	// Compare against caddy_http_request_duration_seconds to see WAF
	// cost as a fraction of total latency.
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

	// ModeInfo is a label-only gauge advertising each route's resolved
	// mode (blocking | detect_only). Always 1; the labels carry the
	// information. Reset and re-populated on every config reload so
	// removed routes drop out and toggled routes flip atomically.
	// Operators query it to display the active mode on dashboards or
	// alert when any route is running in detect_only.
	ModeInfo *prometheus.GaugeVec

	once sync.Once
)

// Init registers all metrics. Idempotent.
func Init() {
	once.Do(func() {
		buildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "waf_build_info",
			Help: "Build-time metadata for the running barbacana binary. Always 1. Label `commit` is the short Git SHA at build time, useful for incident forensics across versions.",
		}, []string{"version", "go_version", "crs_version", "commit"})
		buildInfo.WithLabelValues(version.Version, runtime.Version(), version.CRSVersion, version.Commit).Set(1)

		RequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_requests_total",
			Help: "Total requests processed by the WAF, labelled by action: allowed (clean), detected (matched a protection but not blocked, e.g. detect-only mode), or blocked (halted by a protection in blocking mode). Sum across actions equals total requests handled.",
		}, []string{"route", "action"})

		RequestsInFlight = promauto.NewGauge(prometheus.GaugeOpts{
			Name: "waf_requests_in_flight",
			Help: "Number of requests currently being evaluated by the WAF pipeline. Bumped on entry and released on exit (including panic recovery). Use to spot stuck pipelines: in-flight rising while waf_requests_total rate is flat.",
		})

		UpstreamErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_upstream_errors_total",
			Help: "Proxy-side failures per route and kind: timeout, connection_refused, 5xx (upstream returned status >=500), other. Distinguishes 'WAF blocked' from 'upstream is broken' — caddy_http_requests_total{code=~\"5..\"} conflates the two.",
		}, []string{"route", "kind"})

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

		ModeInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "waf_mode_info",
			Help: "Resolved mode per route as a label-only gauge (always 1). The mode label is one of \"blocking\" or \"detect_only\". Use to display the active mode on dashboards or alert when any route is running in detect_only.",
		}, []string{"route", "mode"})
	})
}

// Handler returns an http.Handler that serves /metrics, gathering from
// both the default Prometheus registry (where waf_*, go_*, and process_*
// series register) and Caddy's per-context registry (where caddy_http_*
// register when the http.metrics module is enabled). Caddy creates a
// fresh registry on every config load, so the pipeline handler invokes
// SetCaddyGatherer from Provision to keep the reference current.
func Handler() http.Handler {
	return promhttp.HandlerFor(combinedGatherer{}, promhttp.HandlerOpts{})
}

var (
	caddyGathererMu sync.RWMutex
	caddyGatherer   prometheus.Gatherer
)

// SetCaddyGatherer registers Caddy's per-context metrics registry so
// the /metrics endpoint exposes caddy_http_* series alongside waf_*
// and the standard Go runtime metrics. Safe to call repeatedly; each
// call replaces the previously-registered gatherer.
func SetCaddyGatherer(g prometheus.Gatherer) {
	caddyGathererMu.Lock()
	caddyGatherer = g
	caddyGathererMu.Unlock()
}

type combinedGatherer struct{}

// Gather merges the default Prometheus registry with Caddy's per-context
// registry. Both register the standard go_* / process_* collectors, so
// merging naively yields duplicate metric families; on a name collision
// the default registry wins and Caddy's copy is dropped. The net effect
// is that Caddy contributes only its own caddy_* series.
//
// TODO: dedup-by-name papers over a real architectural smell. Caddy's
// per-context registry auto-registers go_* / process_* collectors that
// are already on the default registry; the right cleanup is either to
// suppress that auto-registration, or to move all waf_* registration
// onto Caddy's per-context registry and stop using the default one
// entirely. Functional now — revisit when the metrics package gets
// its next non-trivial change.
func (combinedGatherer) Gather() ([]*dto.MetricFamily, error) {
	caddyGathererMu.RLock()
	g := caddyGatherer
	caddyGathererMu.RUnlock()

	defaults, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return nil, err
	}
	if g == nil {
		return defaults, nil
	}
	extras, err := g.Gather()
	if err != nil {
		return defaults, err
	}

	seen := make(map[string]struct{}, len(defaults))
	for _, mf := range defaults {
		seen[mf.GetName()] = struct{}{}
	}
	for _, mf := range extras {
		if _, dup := seen[mf.GetName()]; dup {
			continue
		}
		defaults = append(defaults, mf)
	}
	return defaults, nil
}
