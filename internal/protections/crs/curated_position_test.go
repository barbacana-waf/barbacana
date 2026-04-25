package crs

import (
	"sort"
	"strings"
	"testing"
)

// TestCuratedRulesPosition guards the placement contract for
// curated-rules.conf inside the embedded rules/ tree.
//
// crs.go injects curated-rules.conf just before the first rules/REQUEST-949-*
// file (see blockingEvalPrefix in NewEngine). The injected rules are
// pl1-rewritten copies of pl2/pl3 protocol-attack rules whose canonical
// home is REQUEST-944 (Java) and earlier; they MUST run after every
// REQUEST-9xx attack category and before REQUEST-949 aggregates
// tx.blocking_inbound_anomaly_score. Two upstream changes can silently
// break this contract:
//
//  1. curated-rules.conf is renamed. crs.go's curatedFile constant no
//     longer matches, haveCurated is false, and curated rules silently
//     never load — force-enabled PL2/PL3 detections (e.g. the SMTP
//     command-injection guard) stop firing.
//
//  2. A future CRS upgrade introduces a new file between
//     REQUEST-944-APPLICATION-ATTACK-JAVA.conf and
//     REQUEST-949-BLOCKING-EVALUATION.conf (for example a
//     REQUEST-945-* or REQUEST-946-*). The anchor shifts: curated rules
//     are now injected after that new file too, and any PL1 accumulator
//     state it sets up is silently overridden or skipped.
//
// The test fails loudly so a maintainer is forced to re-evaluate the
// placement instead of letting curated detection degrade unnoticed.
func TestCuratedRulesPosition(t *testing.T) {
	entries, err := FS.ReadDir("rules")
	if err != nil {
		t.Fatalf("read embedded rules/: %v", err)
	}
	files := make([]string, 0, len(entries))
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, ".conf") {
			files = append(files, n)
		}
	}
	sort.Strings(files)

	var haveCurated bool
	for _, f := range files {
		if f == "curated-rules.conf" {
			haveCurated = true
			break
		}
	}
	if !haveCurated {
		t.Fatal("curated-rules.conf is missing from embedded rules/. Curated pl1-rewritten PL2/PL3 rules can only enter the anomaly aggregator via this file; without it, force-enabled detections (e.g. rule 932300 SMTP command injection) silently never fire and the engine builds without complaint.")
	}

	var requestFiles []string
	for _, f := range files {
		if strings.HasPrefix(f, "REQUEST-") {
			requestFiles = append(requestFiles, f)
		}
	}

	idx949 := -1
	for i, f := range requestFiles {
		if strings.HasPrefix(f, "REQUEST-949") {
			idx949 = i
			break
		}
	}
	if idx949 < 0 {
		t.Fatalf("REQUEST-949-*.conf is missing — the engine has no anchor to inject curated rules before, and NewEngine errors at startup. Sorted REQUEST-* files: %v", requestFiles)
	}
	if idx949 == 0 {
		t.Fatalf("REQUEST-949-* is the first REQUEST-* file — expected REQUEST-944 to immediately precede it. Curated PL2/PL3 rules must run after the upstream protocol-attack categories and before REQUEST-949 aggregates tx.blocking_inbound_anomaly_score. If a new CRS file has been added that pushes REQUEST-944 elsewhere, the curated-rules placement contract needs revisiting. Sorted REQUEST-* files: %v", requestFiles)
	}
	prev := requestFiles[idx949-1]
	if !strings.HasPrefix(prev, "REQUEST-944") {
		t.Fatalf(
			"REQUEST-949-* is no longer immediately preceded by REQUEST-944-*: got %q before %q. "+
				"crs.go injects curated-rules.conf just before the first REQUEST-949-* file; "+
				"a new file appearing between REQUEST-944 and REQUEST-949 silently shifts the anchor "+
				"and curated PL1-rewritten setvars may run after rules they were tuned to feed. "+
				"Re-evaluate the placement (see internal/protections/crs/crs.go's blockingEvalPrefix). "+
				"Sorted REQUEST-* files: %v",
			prev, requestFiles[idx949], requestFiles)
	}
}
