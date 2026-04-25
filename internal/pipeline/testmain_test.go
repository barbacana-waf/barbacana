package pipeline

import (
	"os"
	"testing"

	"github.com/barbacana-waf/barbacana/internal/metrics"
)

// TestMain initialises the Prometheus registry once for every test in the
// pipeline package. Shared across the default and `integration`-tagged
// builds so each binary has exactly one TestMain.
func TestMain(m *testing.M) {
	metrics.Init()
	os.Exit(m.Run())
}
