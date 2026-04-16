package cmd

import (
	"fmt"
	"os"
)

// Execute is the CLI entry point. A8 wires only `serve`; the `validate`,
// `defaults`, `debug`, and `version` subcommands land in C4.
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
  barbacana serve --config <path>

Subcommands arriving in later phases: validate, defaults, debug, version.
`)
}
