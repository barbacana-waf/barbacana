package crs

import (
	"sort"
	"strings"
	"testing"
)

// TestCuratedRulesPosition pins the contract that crs.go relies on when
// it inserts the curated phase files before their respective blocking-
// evaluation files:
//
//  1. curated-rules-request.conf and curated-rules-response.conf must
//     be present in the embedded FS so the load loop in crs.go can read
//     them.
//  2. In the lexicographically-sorted REQUEST-* slice, the file
//     immediately preceding REQUEST-949-BLOCKING-EVALUATION.conf must
//     start with REQUEST-944. Mirror constraint on the response side:
//     the file immediately preceding RESPONSE-959-BLOCKING-EVALUATION.conf
//     must start with RESPONSE-955 or RESPONSE-956. A new file appearing
//     between either pair means the placement strategy must be re-
//     evaluated and this test forces that reckoning.
func TestCuratedRulesPosition(t *testing.T) {
	entries, err := FS.ReadDir("rules")
	if err != nil {
		t.Fatalf("read rules dir: %v", err)
	}

	var requestFiles, responseFiles []string
	curatedRequest := false
	curatedResponse := false
	for _, e := range entries {
		name := e.Name()
		switch name {
		case "curated-rules-request.conf":
			curatedRequest = true
			continue
		case "curated-rules-response.conf":
			curatedResponse = true
			continue
		}
		if !strings.HasSuffix(name, ".conf") {
			continue
		}
		if strings.HasPrefix(name, "REQUEST-") {
			requestFiles = append(requestFiles, name)
		}
		if strings.HasPrefix(name, "RESPONSE-") {
			responseFiles = append(responseFiles, name)
		}
	}

	if !curatedRequest {
		t.Fatal("curated-rules-request.conf missing from embedded rules/ — " +
			"crs.go relies on it to inject curated phase-1/2 rules before " +
			"REQUEST-949-BLOCKING-EVALUATION.conf aggregates the inbound score.")
	}
	if !curatedResponse {
		t.Fatal("curated-rules-response.conf missing from embedded rules/ — " +
			"crs.go relies on it to inject curated phase-3/4 rules before " +
			"RESPONSE-959-BLOCKING-EVALUATION.conf aggregates the outbound score.")
	}

	sort.Strings(requestFiles)
	checkAnchor(t, requestFiles, "REQUEST-949", "REQUEST-944")

	sort.Strings(responseFiles)
	// The predecessor of RESPONSE-959 is whichever of RESPONSE-955 /
	// RESPONSE-956 ships in the pinned CRS — accept either prefix.
	checkAnchor(t, responseFiles, "RESPONSE-959", "RESPONSE-955", "RESPONSE-956")
}

func checkAnchor(t *testing.T, files []string, blockingPrefix string, allowedPrev ...string) {
	t.Helper()
	idx := -1
	for i, f := range files {
		if strings.HasPrefix(f, blockingPrefix) {
			idx = i
			break
		}
	}
	if idx == -1 {
		t.Fatalf("no %s* file in embedded rules — curated rules cannot be placed before blocking evaluation", blockingPrefix)
	}
	if idx == 0 {
		t.Fatalf("%s* is the first file in its slice (no predecessor); curated rules placement contract is broken", blockingPrefix)
	}
	prev := files[idx-1]
	for _, p := range allowedPrev {
		if strings.HasPrefix(prev, p) {
			return
		}
	}
	t.Fatalf("anchor shifted: file immediately preceding %s* is %q, want one of %v. "+
		"crs.go assumes the curated file sits between this predecessor and "+
		"the blocking-evaluation file so its matches feed the anomaly aggregator. "+
		"A new file appearing here (e.g. from a CRS upgrade) means the "+
		"placement strategy must be re-evaluated.", blockingPrefix, prev, allowedPrev)
}
