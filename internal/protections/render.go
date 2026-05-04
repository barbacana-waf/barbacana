package protections

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrLeafNotFound is returned by RenderLeaf when no leaf matches the
// requested ID.
var ErrLeafNotFound = errors.New("leaf not found")

// RenderMarkdown returns a markdown view of the entire Catalog: one ## per
// L1 family, one ### per L2 bucket where bucketed, leaf tables with the
// columns from the proposal (ID, Default, CWE, RuleIDs, WhatItDoes).
//
// The output is intended for the `barbacana --catalog` CLI flag and for
// copy-pasting into the public-docs repo.
func RenderMarkdown() string {
	var b strings.Builder
	b.WriteString("# WAF Protection Catalog\n\n")
	for _, g := range Catalog {
		fmt.Fprintf(&b, "## %s\n\n", g.ID)
		if g.Description != "" {
			fmt.Fprintf(&b, "%s\n\n", g.Description)
		}
		if g.WhyDisable != "" {
			fmt.Fprintf(&b, "**L1-level disable:** *%s*\n\n", g.WhyDisable)
		}
		if len(g.Leaves) > 0 {
			renderLeafTable(&b, g.Leaves)
		}
		for _, bucket := range g.Buckets {
			fmt.Fprintf(&b, "### %s\n\n", bucket.ID)
			if bucket.Description != "" {
				fmt.Fprintf(&b, "%s\n\n", bucket.Description)
			}
			if bucket.WhyDisable != "" {
				fmt.Fprintf(&b, "**L2-level disable:** *%s*\n\n", bucket.WhyDisable)
			}
			renderLeafTable(&b, bucket.Leaves)
		}
	}
	return b.String()
}

// RenderLeaf returns a markdown detail block for a single leaf (the output
// of `barbacana --catalog-leaf <name>`). Returns ErrLeafNotFound if the ID
// doesn't resolve.
func RenderLeaf(id string) (string, error) {
	leaf, group, bucket, ok := LookupLeaf(id)
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrLeafNotFound, id)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", leaf.ID)
	if bucket.ID != "" {
		fmt.Fprintf(&b, "Family: `%s` › `%s`\n\n", group.ID, bucket.ID)
	} else {
		fmt.Fprintf(&b, "Family: `%s`\n\n", group.ID)
	}
	fmt.Fprintf(&b, "- Default: `%s`\n", leaf.Default)
	fmt.Fprintf(&b, "- CWE: %s\n", formatCWE(leaf.CWE))
	fmt.Fprintf(&b, "- Rule IDs: %s\n\n", formatRuleIDs(leaf.RuleIDs))
	fmt.Fprintf(&b, "## What it does\n\n%s\n\n", leaf.WhatItDoes)
	if leaf.WhyDisable != "" {
		fmt.Fprintf(&b, "## Why disable\n\n%s\n\n", leaf.WhyDisable)
	}
	if leaf.WhyEnable != "" {
		fmt.Fprintf(&b, "## Why enable\n\n%s\n\n", leaf.WhyEnable)
	}
	return b.String(), nil
}

func renderLeafTable(b *strings.Builder, leaves []Leaf) {
	b.WriteString("| ID | Default | CWE | Rule IDs | What it does | When to toggle |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, l := range leaves {
		fmt.Fprintf(b, "| `%s` | %s | %s | %s | %s | %s |\n",
			l.ID, l.Default,
			formatCWE(l.CWE), formatRuleIDs(l.RuleIDs),
			escapeTableCell(l.WhatItDoes),
			escapeTableCell(toggleProse(l)))
	}
	b.WriteString("\n")
}

func toggleProse(l Leaf) string {
	switch {
	case l.WhyDisable != "":
		return l.WhyDisable
	case l.WhyEnable != "":
		return l.WhyEnable
	default:
		return "—"
	}
}

func formatCWE(cwes []int) string {
	if len(cwes) == 0 {
		return "—"
	}
	sorted := append([]int(nil), cwes...)
	sort.Ints(sorted)
	parts := make([]string, len(sorted))
	for i, c := range sorted {
		parts[i] = fmt.Sprintf("CWE-%d", c)
	}
	return strings.Join(parts, ", ")
}

func formatRuleIDs(ids []string) string {
	if len(ids) == 0 {
		return "—"
	}
	return strings.Join(ids, ", ")
}

func escapeTableCell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
