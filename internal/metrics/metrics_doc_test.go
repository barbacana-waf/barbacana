package metrics

import (
	"os"
	"regexp"
	"testing"
)

// TestEveryMetricIsDocumented keeps the metrics table in
// docs/design/architecture.md complete: every waf_* metric registered in
// metrics.go must have a row there. The public metrics page is written from
// that table, so a metric missing from it stays invisible to operators.
func TestEveryMetricIsDocumented(t *testing.T) {
	src, err := os.ReadFile("metrics.go")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile("../../docs/design/architecture.md")
	if err != nil {
		t.Fatal(err)
	}

	names := regexp.MustCompile(`Name:\s*"(waf_[a-z0-9_]+)"`).FindAllSubmatch(src, -1)
	if len(names) < 10 {
		t.Fatalf("found only %d metric names in metrics.go; has the registration style changed?", len(names))
	}
	for _, m := range names {
		row := regexp.MustCompile("(?m)^\\| `" + regexp.QuoteMeta(string(m[1])) + "` \\|")
		if !row.Match(doc) {
			t.Errorf("metric %s has no row in the metrics table of docs/design/architecture.md", m[1])
		}
	}
}
