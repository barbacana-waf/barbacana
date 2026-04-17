package headers

import (
	"os"
	"testing"

	"github.com/barbacana-waf/barbacana/internal/metrics"
)

func TestMain(m *testing.M) {
	metrics.Init()
	os.Exit(m.Run())
}
