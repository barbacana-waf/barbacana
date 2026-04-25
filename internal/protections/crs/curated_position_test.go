package crs

import (
	"sort"
	"strings"
	"testing"
)

// TestCuratedRulesPosition pins the contract that crs.go relies on when it
// inserts curated-rules.conf before REQUEST-949-BLOCKING-EVALUATION.conf:
//
//  1. curated-rules.conf must be present in the embedded FS so the load
//     loop in crs.go can read it.
//  2. In the lexicographically-sorted REQUEST-* slice, the file immediately
//     preceding REQUEST-949-BLOCKING-EVALUATION.conf must start with
//     REQUEST-944. crs.go injects curated rules at the first REQUEST-949*
//     file; if a future CRS upgrade introduces a REQUEST-945..948 file, the
//     curated PL2/PL3 rules would still be injected before REQUEST-949 (so
//     the anomaly aggregator still sees them), but the assumption documented
//     in the comment block in crs.go ("Inserting between REQUEST-944 and
//     REQUEST-949 in lexicographic order satisfies both") would no longer
//     hold. Failing this test forces a re-evaluation of that comment and the
//     placement strategy.
func TestCuratedRulesPosition(t *testing.T) {
	entries, err := FS.ReadDir("rules")
	if err != nil {
		t.Fatalf("read rules dir: %v", err)
	}

	var requestFiles []string
	curatedPresent := false
	for _, e := range entries {
		name := e.Name()
		if name == "curated-rules.conf" {
			curatedPresent = true
			continue
		}
		if strings.HasPrefix(name, "REQUEST-") && strings.HasSuffix(name, ".conf") {
			requestFiles = append(requestFiles, name)
		}
	}

	if !curatedPresent {
		t.Fatal("curated-rules.conf missing from embedded rules/ — " +
			"crs.go relies on it to inject curated PL2/PL3 rules before " +
			"REQUEST-949-BLOCKING-EVALUATION.conf aggregates the anomaly score. " +
			"Without it, curated rules never load and detection silently degrades.")
	}

	sort.Strings(requestFiles)

	idx949 := -1
	for i, f := range requestFiles {
		if strings.HasPrefix(f, "REQUEST-949") {
			idx949 = i
			break
		}
	}
	if idx949 == -1 {
		t.Fatal("no REQUEST-949* file in embedded rules — " +
			"curated rules cannot be placed before blocking evaluation.")
	}
	if idx949 == 0 {
		t.Fatalf("REQUEST-949* is the first REQUEST-* file (no predecessor); " +
			"curated rules placement contract is broken.")
	}

	prev := requestFiles[idx949-1]
	if !strings.HasPrefix(prev, "REQUEST-944") {
		t.Fatalf("anchor shifted: file immediately preceding REQUEST-949* in "+
			"sorted REQUEST-* slice is %q, want REQUEST-944*. "+
			"crs.go assumes curated-rules.conf sits between REQUEST-944 and "+
			"REQUEST-949 so its phase-2 matches feed the anomaly aggregator. "+
			"A new file appearing here (e.g. from a CRS upgrade) means the "+
			"placement strategy must be re-evaluated.", prev)
	}
}
