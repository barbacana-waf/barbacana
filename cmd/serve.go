package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/caddyserver/caddy/v2"

	"github.com/barbacana-waf/barbacana/internal/audit"
	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/health"
	"github.com/barbacana-waf/barbacana/internal/metrics"
	"github.com/barbacana-waf/barbacana/internal/pipeline"
)

// DefaultConfigPath is the path Barbacana reads when --config is omitted.
// Matches the mount point used by the published container image and
// compose.yaml, so `docker run ...` works without args.
const DefaultConfigPath = "/etc/barbacana/waf.yaml"

func runServe(configPath string) error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Register metrics unconditionally. Protection handlers, Coraza, and
	// reload all reference these vectors; guarding every call site with a
	// nil check would be much noisier than just keeping the counters in
	// memory. The /metrics endpoint is gated separately below — when
	// disabled the counters still increment but nothing exposes them.
	metrics.Init()

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	resolved, err := config.Resolve(cfg)
	if err != nil {
		return fmt.Errorf("resolve config: %w", err)
	}
	warnDetectOnly(resolved, logger)
	pipeline.RegisterConfigs(resolved)

	// Audit log format is process-wide; validation guarantees the
	// value is "ocsf" or "ecs" by the time we get here.
	audit.SetFormat(config.ResolveAudit(cfg).Format)

	// Tracing is opt-in. With it disabled, the returned Provider is a
	// no-op shell — drainTracing on it is harmless. See cmd/observability_setup.go.
	traceProvider, err := setupTracing(cfg)
	if err != nil {
		return err
	}
	defer drainTracing(traceProvider, logger)

	caddyJSON, err := config.Compile(cfg, resolved)
	if err != nil {
		return fmt.Errorf("compile caddy config: %w", err)
	}

	if err := caddy.Load(caddyJSON, false); err != nil {
		return fmt.Errorf("start caddy: %w", err)
	}

	// Health and metrics servers are opt-in (principle 10). A zero port
	// means "not started": the listener is never created, no endpoint is
	// exposed, and the server variable stays nil so shutdown is a no-op.
	var healthSrv *http.Server
	if cfg.HealthPort > 0 {
		healthSrv = newAuxServer(portAddr(cfg.HealthPort), health.Handler())
		go serve(healthSrv, "health", logger)
	} else {
		logger.Info("health endpoint disabled — set health_port to enable /healthz and /readyz")
	}

	var metricsSrv *http.Server
	if cfg.MetricsPort > 0 {
		metricsSrv = newAuxServer(portAddr(cfg.MetricsPort), metrics.Handler())
		go serve(metricsSrv, "metrics", logger)
	} else {
		logger.Info("metrics endpoint disabled — set metrics_port to enable /metrics")
	}

	var pprofSrv *http.Server
	if pprofAddr := os.Getenv("BARBACANA_PPROF_PORT"); pprofAddr != "" {
		pprofSrv = newAuxServer(":"+pprofAddr, http.DefaultServeMux)
		go serve(pprofSrv, "pprof", logger)
		logger.Warn("pprof endpoint enabled — do not expose in production", "port", pprofAddr)
	}

	logger.Info("barbacana started",
		"mode", deploymentMode(cfg),
		"host", strings.Join(cfg.Hosts, ","),
		"port", cfg.Port,
		"health_port", cfg.HealthPort,
		"metrics_port", cfg.MetricsPort,
		"routes", len(cfg.Routes),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = waitForSignals(ctx, &reloader{path: configPath, logger: logger, cfg: cfg, resolved: resolved})
	if healthSrv != nil {
		shutdownAux(healthSrv, "health", logger)
	}
	if metricsSrv != nil {
		shutdownAux(metricsSrv, "metrics", logger)
	}
	if pprofSrv != nil {
		shutdownAux(pprofSrv, "pprof", logger)
	}
	return err
}

func portAddr(port int) string {
	return ":" + strconv.Itoa(port)
}

// warnDetectOnly logs a warning for every route running in detect_only
// mode. Operators opting into observation-only behaviour need a loud
// reminder at startup that malicious requests are being logged, not
// blocked (principle 11).
func warnDetectOnly(routes []config.Resolved, logger *slog.Logger) {
	for _, r := range routes {
		if r.Mode == config.ModeDetect {
			logger.Warn("route in detect_only mode — attacks are logged but NOT blocked", "route", r.ID)
		}
	}
}

func deploymentMode(cfg *config.Config) string {
	if len(cfg.Hosts) > 0 {
		return "single-host-auto-tls"
	}
	for _, r := range cfg.Routes {
		if r.Match != nil && len(r.Match.Hosts) > 0 {
			return "multi-host-auto-tls"
		}
	}
	return "plain-http"
}

func newAuxServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

func serve(s *http.Server, name string, logger *slog.Logger) {
	if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("aux server failed", "name", name, "err", err.Error())
	}
}

func shutdownAux(s *http.Server, name string, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		logger.Error("aux shutdown failed", "name", name, "err", err.Error())
	}
}

func waitForSignals(ctx context.Context, rl *reloader) error {
	logger := rl.logger
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case <-ctx.Done():
			return nil
		case s := <-sigs:
			switch s {
			case syscall.SIGHUP:
				if err := rl.reload(); err != nil {
					logger.Error("reload failed", "err", err.Error())
				}
			case syscall.SIGINT, syscall.SIGTERM:
				logger.Info("shutting down", "signal", s.String())
				if err := caddy.Stop(); err != nil {
					return fmt.Errorf("stop caddy: %w", err)
				}
				return nil
			}
		}
	}
}

// reloader holds what a SIGHUP reload needs to know about the running
// configuration: the YAML it came from, to detect settings that cannot change
// without a restart, and its resolved routes, to put back if a reload fails.
type reloader struct {
	path     string
	logger   *slog.Logger
	cfg      *config.Config
	resolved []config.Resolved
}

// reload re-reads the config file and swaps it into the running server. It
// either applies the whole new config or leaves the running one untouched.
//
// Everything that can fail without side effects (load, resolve, compile)
// runs before the route registry is touched. The registry has to hold the new
// routes while caddy.Load runs, because each handler reads its resolved
// config from it when Caddy provisions the new config. If caddy.Load then
// fails, Caddy keeps serving the old handlers, so the previous routes go back
// into the registry to keep it describing what is actually running.
//
// Load is forced because the Caddy JSON only carries each route's ID, upstream
// and match: a change to a route's protections, limits or mode leaves it
// byte-identical, and an unforced Load would skip the reload as "unchanged"
// while still reporting success.
func (rl *reloader) reload() error {
	fail := func(err error) error {
		metrics.ConfigReloadTotal.WithLabelValues("error").Inc()
		return err
	}

	cfg, err := config.Load(rl.path)
	if err != nil {
		return fail(err)
	}
	resolved, err := config.Resolve(cfg)
	if err != nil {
		return fail(err)
	}
	caddyJSON, err := config.Compile(cfg, resolved)
	if err != nil {
		return fail(err)
	}

	pipeline.RegisterConfigs(resolved)
	if err := caddy.Load(caddyJSON, true); err != nil {
		pipeline.RegisterConfigs(rl.resolved)
		return fail(err)
	}

	warnDetectOnly(resolved, rl.logger)
	if changed := startupOnlyChanges(rl.cfg, cfg); len(changed) > 0 {
		rl.logger.Warn("config reloaded, but these settings are only read at startup and keep their old values until barbacana is restarted",
			"settings", strings.Join(changed, ","))
	}
	rl.cfg, rl.resolved = cfg, resolved

	metrics.ConfigReloadTotal.WithLabelValues("success").Inc()
	metrics.ConfigReloadTimestamp.SetToCurrentTime()
	rl.logger.Info("config reloaded", "path", rl.path)
	return nil
}

// startupOnlyChanges names the settings that differ between two configs but
// are applied once, in runServe, and so ignore a reload: the health and
// metrics listeners, tracing, and the audit log format. Everything else,
// including the listen address, hosts and data_dir, is applied by Caddy.
func startupOnlyChanges(old, cur *config.Config) []string {
	var changed []string
	if old.HealthPort != cur.HealthPort {
		changed = append(changed, "health_port")
	}
	if old.MetricsPort != cur.MetricsPort {
		changed = append(changed, "metrics_port")
	}
	if !reflect.DeepEqual(old.Tracing, cur.Tracing) {
		changed = append(changed, "tracing")
	}
	if old.AuditLog != cur.AuditLog {
		changed = append(changed, "audit_log")
	}
	return changed
}
