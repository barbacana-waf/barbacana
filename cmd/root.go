package cmd

import (
	"fmt"
	"os"
)

// Execute is the CLI entry point.
func Execute() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	sub := os.Args[1]
	args := os.Args[2:]
	switch sub {
	case "serve":
		if err := runServe(args); err != nil {
			fmt.Fprintf(os.Stderr, "barbacana serve: %v\n", err)
			os.Exit(1)
		}
	case "validate":
		if err := runValidate(args); err != nil {
			fmt.Fprintf(os.Stderr, "barbacana validate: %v\n", err)
			os.Exit(1)
		}
	case "defaults":
		runDefaults()
	case "debug":
		if err := runDebug(args); err != nil {
			fmt.Fprintf(os.Stderr, "barbacana debug: %v\n", err)
			os.Exit(1)
		}
	case "version":
		runVersion()
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "barbacana: unknown subcommand %q\n", sub)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `barbacana — open-source WAF and API security gateway

Usage:
  barbacana serve [--config <path>]  Start the WAF proxy (default /etc/barbacana/waf.yaml)
  barbacana validate <config>        Validate config without starting
  barbacana defaults                 Print all protections with defaults
  barbacana debug render-config <config>  Output generated Caddy config
  barbacana version                  Print version info
`)
}
