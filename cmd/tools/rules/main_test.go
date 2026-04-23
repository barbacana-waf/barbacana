package main

import (
	"os"
	"strings"
	"testing"

	"github.com/barbacana-waf/barbacana/internal/protections/crs/curated"
)

func TestReadCRSVersion(t *testing.T) {
	dir := t.TempDir()
	mk := dir + "/versions.mk"
	if err := writeFile(mk, "BARBACANA_VERSION=v0.1.0\nCRS_VERSION=v4.25.0\nFOO=bar\n"); err != nil {
		t.Fatal(err)
	}
	got, err := readCRSVersion(mk)
	if err != nil {
		t.Fatal(err)
	}
	if got != "v4.25.0" {
		t.Errorf("got %q, want v4.25.0", got)
	}
}

func TestReadChecksumTrimsWhitespace(t *testing.T) {
	dir := t.TempDir()
	f := dir + "/CRS_SHA256"
	// sha256sum output format: "<hex>  <filename>\n"
	if err := writeFile(f, "89772237c36e9ef8475ad3981fff1df08a449dd9ccd2fedef42c4f691f00d33e  crs-v4.25.0.tar.gz\n"); err != nil {
		t.Fatal(err)
	}
	got, err := readCheckum(f)
	if err != nil {
		t.Fatal(err)
	}
	if got != "89772237c36e9ef8475ad3981fff1df08a449dd9ccd2fedef42c4f691f00d33e" {
		t.Errorf("got %q", got)
	}
}

func TestRewriteScoreAccumulators(t *testing.T) {
	in := `SecRule x "@rx y" "id:1,setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}',setvar:'tx.inbound_anomaly_score_pl3=+%{tx.error_anomaly_score}'"`
	got := rewriteScoreAccumulators(in)
	if strings.Contains(got, "inbound_anomaly_score_pl2") || strings.Contains(got, "inbound_anomaly_score_pl3") {
		t.Errorf("rewrite left pl2/pl3 behind: %s", got)
	}
	if strings.Count(got, "inbound_anomaly_score_pl1=") != 2 {
		t.Errorf("expected exactly two pl1 assignments, got: %s", got)
	}
}

// TestExtractSecRuleBlocks verifies: (a) chain starter + indented
// continuation stay in one block, (b) blank line ends a block, (c)
// only requested IDs are returned, (d) unrequested neighbouring rules
// do not bleed into the selected block.
func TestExtractSecRuleBlocks(t *testing.T) {
	input := `# header
SecRule ARGS "@rx foo" \
    "id:100,\
    phase:2,\
    pass"

SecRule ARGS "@rx bar" \
    "id:200,\
    phase:2,\
    chain"
    SecRule ARGS "@rx baz"

SecRule ARGS "@rx unused" \
    "id:300,phase:2"
`
	got := extractSecRuleBlocks(input, []int{100, 200})
	if _, ok := got[100]; !ok {
		t.Errorf("missing rule 100")
	}
	if _, ok := got[300]; ok {
		t.Errorf("rule 300 should not have been extracted")
	}
	block200, ok := got[200]
	if !ok {
		t.Fatalf("missing rule 200")
	}
	if !strings.Contains(block200, "SecRule ARGS \"@rx baz\"") {
		t.Errorf("chain continuation dropped from rule 200 block:\n%s", block200)
	}
	if strings.Contains(block200, "unused") {
		t.Errorf("rule 200 block bled into next rule:\n%s", block200)
	}
}

// TestSourceFileForIDCoversAllCurated is a build-time guarantee that
// every curated rule prefix has a source file mapping. Catches a
// curated-set change that adds a new 9xx prefix without updating
// sourceFileForID.
func TestSourceFileForIDCoversAllCurated(t *testing.T) {
	for _, r := range curated.Rules {
		if _, err := sourceFileForID(r.ID); err != nil {
			t.Errorf("no source file for curated rule %d: %v", r.ID, err)
		}
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
