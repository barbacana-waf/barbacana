package cmd

import (
	"fmt"
	"os"

	"github.com/barbacana-waf/barbacana/internal/protections"
)

// runCatalogList prints the full protection catalog as markdown. Backs the
// --catalog flag.
func runCatalogList() error {
	_, err := fmt.Fprint(os.Stdout, protections.RenderMarkdown())
	return err
}

// runCatalogShow prints a single leaf's detail block as markdown. Backs the
// --catalog-leaf flag.
func runCatalogShow(leafID string) error {
	out, err := protections.RenderLeaf(leafID)
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(os.Stdout, out)
	return err
}
