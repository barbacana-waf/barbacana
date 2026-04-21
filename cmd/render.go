package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/barbacana-waf/barbacana/internal/config"
)

func runRenderConfig(path string) error {
	if path == "" {
		return errors.New("config path is required")
	}

	cfg, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	resolved, err := config.Resolve(cfg)
	if err != nil {
		return fmt.Errorf("resolve config: %w", err)
	}

	caddyJSON, err := config.Compile(cfg, resolved)
	if err != nil {
		return fmt.Errorf("compile config: %w", err)
	}

	var pretty json.RawMessage
	if err := json.Unmarshal(caddyJSON, &pretty); err != nil {
		_, _ = os.Stdout.Write(caddyJSON)
		return nil
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(pretty)
}
