package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/protections/openapi"
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

	// The handler loads each OpenAPI spec when it starts, so a missing or
	// malformed spec would pass everything above and then stop the server
	// from starting. Load them here too, the same way, and report every bad
	// one rather than the first.
	var specErrs []string
	for i := range resolved {
		route := &resolved[i]
		if route.OpenAPI == nil || route.OpenAPI.Spec == "" {
			continue
		}
		if _, err := openapi.NewValidator(route.OpenAPI.Spec, *route); err != nil {
			specErrs = append(specErrs, fmt.Sprintf("route %q: %v", route.ID, err))
		}
	}
	if len(specErrs) > 0 {
		return fmt.Errorf("openapi spec: %s", strings.Join(specErrs, "\n"))
	}

	fmt.Println("config valid")
	return nil
}
