package cmd

import (
	"errors"
	"flag"
	"fmt"

	"github.com/barbacana-waf/barbacana/internal/config"
)

func runValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("usage: barbacana validate <config>")
	}
	path := fs.Arg(0)

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
