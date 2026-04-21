package cmd

import (
	"errors"
	"fmt"

	"github.com/barbacana-waf/barbacana/internal/config"
)

func runValidate(path string) error {
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

	if _, err := config.Compile(cfg, resolved); err != nil {
		return fmt.Errorf("compile config: %w", err)
	}

	fmt.Println("config valid")
	return nil
}
