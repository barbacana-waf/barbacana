package cmd

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/barbacana-waf/barbacana/internal/config"
)

func runDebug(args []string) error {
	fs := flag.NewFlagSet("debug", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 || fs.Arg(0) != "render-config" {
		return errors.New("usage: barbacana debug render-config <config>")
	}
	path := fs.Arg(1)

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

	// Pretty-print the Caddy JSON.
	var pretty json.RawMessage
	if err := json.Unmarshal(caddyJSON, &pretty); err != nil {
		// If unmarshal fails, output the raw bytes.
		_, _ = os.Stdout.Write(caddyJSON)
		return nil
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(pretty)
}
