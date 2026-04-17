package cmd

import (
	"fmt"
	"runtime"

	"github.com/barbacana-waf/barbacana/internal/version"
)

func runVersion() {
	fmt.Printf("barbacana %s (%s)\n", version.Version, version.Commit)
	fmt.Printf("go        %s\n", runtime.Version())
	fmt.Printf("crs       %s\n", version.CRSVersion)
}
