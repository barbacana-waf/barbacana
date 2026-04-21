package cmd

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

// Execute is the CLI entry point.
func Execute() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

// run parses args and dispatches to the selected mode. It is split from
// Execute so tests can drive it without touching os.Exit.
func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("barbacana", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }

	configPath := fs.String("config", DefaultConfigPath, "path to the barbacana YAML config")
	validate := fs.Bool("validate", false, "validate the config and exit")
	renderConfig := fs.Bool("render-config", false, "print the compiled Caddy JSON and exit")
	showVersion := fs.Bool("version", false, "print version info and exit")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	modes := 0
	if *validate {
		modes++
	}
	if *renderConfig {
		modes++
	}
	if *showVersion {
		modes++
	}
	if modes > 1 {
		fmt.Fprintln(stderr, "barbacana: --validate, --render-config, and --version are mutually exclusive")
		usage(stderr)
		return 2
	}

	switch {
	case *showVersion:
		runVersion()
		return 0
	case *validate:
		if err := runValidate(*configPath); err != nil {
			fmt.Fprintf(stderr, "barbacana: %v\n", err)
			return 1
		}
		return 0
	case *renderConfig:
		if err := runRenderConfig(*configPath); err != nil {
			fmt.Fprintf(stderr, "barbacana: %v\n", err)
			return 1
		}
		return 0
	default:
		if err := runServe(*configPath); err != nil {
			fmt.Fprintf(stderr, "barbacana: %v\n", err)
			return 1
		}
		return 0
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `barbacana — open-source WAF and API security gateway

Usage:
  barbacana [flags]

Flags:
  --config <path>   Path to the YAML config (default /etc/barbacana/waf.yaml)
  --validate        Validate the config and exit
  --render-config   Print the compiled Caddy JSON and exit
  --version         Print version info and exit
  -h, --help        Show this help

Examples:
  barbacana
  barbacana --config ./waf.yaml
  barbacana --config ./waf.yaml --validate
  barbacana --config ./waf.yaml --render-config
  barbacana --version
`)
}
