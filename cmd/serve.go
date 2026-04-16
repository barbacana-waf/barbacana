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
	"syscall"
	"time"

	"github.com/caddyserver/caddy/v2"

	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/health"
	"github.com/barbacana-waf/barbacana/internal/metrics"
	"github.com/barbacana-waf/barbacana/internal/pipeline"
)

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to the barbacana YAML config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" {
		return errors.New("--config is required")
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

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

	healthSrv := newAuxServer(cfg.HealthListen, health.Handler())
	metricsSrv := newAuxServer(cfg.MetricsListen, metrics.Handler())
	go serve(healthSrv, "health", logger)
	go serve(metricsSrv, "metrics", logger)

	logger.Info("barbacana started",
		"listen", cfg.Listen,
		"health_listen", cfg.HealthListen,
		"metrics_listen", cfg.MetricsListen,
		"routes", len(cfg.Routes),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = waitForSignals(ctx, *configPath, logger)
	shutdownAux(healthSrv, "health", logger)
	shutdownAux(metricsSrv, "metrics", logger)
	return err
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
		return err
	}
	resolved, err := config.Resolve(cfg)
	if err != nil {
		return err
	}
	pipeline.RegisterConfigs(resolved)
	caddyJSON, err := config.Compile(cfg, resolved)
	if err != nil {
		return err
	}
	if err := caddy.Load(caddyJSON, false); err != nil {
		return err
	}
	logger.Info("config reloaded", "path", path)
	return nil
}
