package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/caddyserver/caddy/v2"

	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/health"
	"github.com/barbacana-waf/barbacana/internal/metrics"
	"github.com/barbacana-waf/barbacana/internal/pipeline"
)

// DefaultConfigPath is the path Barbacana reads when --config is omitted.
// Matches the mount point used by the published container image and
// compose.yaml, so `docker run ... barbacana serve` works without args.
const DefaultConfigPath = "/etc/barbacana/waf.yaml"

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", DefaultConfigPath, "path to the barbacana YAML config")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Register metrics unconditionally. Protection handlers, Coraza, and
	// reload all reference these vectors; guarding every call site with a
	// nil check would be much noisier than just keeping the counters in
	// memory. The /metrics endpoint is gated separately below — when
	// disabled the counters still increment but nothing exposes them.
	metrics.Init()

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	resolved, err := config.Resolve(cfg)
	if err != nil {
		return fmt.Errorf("resolve config: %w", err)
	}
	pipeline.RegisterConfigs(resolved)

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

	logger.Info("barbacana started",
		"mode", deploymentMode(cfg),
		"host", cfg.Host,
		"port", cfg.Port,
		"health_port", cfg.HealthPort,
		"metrics_port", cfg.MetricsPort,
		"routes", len(cfg.Routes),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = waitForSignals(ctx, *configPath, logger)
	if healthSrv != nil {
		shutdownAux(healthSrv, "health", logger)
	}
	if metricsSrv != nil {
		shutdownAux(metricsSrv, "metrics", logger)
	}
	return err
}

func portAddr(port int) string {
	return ":" + strconv.Itoa(port)
}

func deploymentMode(cfg *config.Config) string {
	if cfg.Host != "" {
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

func waitForSignals(ctx context.Context, configPath string, logger *slog.Logger) error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case <-ctx.Done():
			return nil
		case s := <-sigs:
			switch s {
			case syscall.SIGHUP:
				if err := reload(configPath, logger); err != nil {
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

func reload(path string, logger *slog.Logger) error {
	cfg, err := config.Load(path)
	if err != nil {
		metrics.ConfigReloadTotal.WithLabelValues("error").Inc()
		return err
	}
	resolved, err := config.Resolve(cfg)
	if err != nil {
		metrics.ConfigReloadTotal.WithLabelValues("error").Inc()
		return err
	}
	pipeline.RegisterConfigs(resolved)
	caddyJSON, err := config.Compile(cfg, resolved)
	if err != nil {
		metrics.ConfigReloadTotal.WithLabelValues("error").Inc()
		return err
	}
	if err := caddy.Load(caddyJSON, false); err != nil {
		metrics.ConfigReloadTotal.WithLabelValues("error").Inc()
		return err
	}
	metrics.ConfigReloadTotal.WithLabelValues("success").Inc()
	metrics.ConfigReloadTimestamp.SetToCurrentTime()
	logger.Info("config reloaded", "path", path)
	return nil
}
