package cmd

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/barbacana-waf/barbacana/internal/protections"
)

func runDefaults() {
	catalog := protections.Catalog()
	cweMap := protections.CWEMap()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "PROTECTION\tSTATUS\tCWE")

	// Sort categories for stable output.
	categories := make([]string, 0, len(catalog))
	for cat := range catalog {
		categories = append(categories, cat)
	}
	sort.Strings(categories)

	for _, cat := range categories {
		subs := catalog[cat]
		cwe := cweMap[cat]
		if cwe == "" {
			cwe = "-"
		}
		_, _ = fmt.Fprintf(w, "%s\tenabled\t%s\n", cat, cwe)

		// Sub-protections are already sorted in catalog order; sort for stability.
		sorted := make([]string, len(subs))
		copy(sorted, subs)
		sort.Strings(sorted)

		for _, sub := range sorted {
			cwe := cweMap[sub]
			if cwe == "" {
				cwe = "-"
			}
			_, _ = fmt.Fprintf(w, "  %s\tenabled\t%s\n", sub, cwe)
		}
	}
	_ = w.Flush()
}
