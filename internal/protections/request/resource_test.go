package request

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"runtime"
	"testing"
	"time"

	"github.com/barbacana-waf/barbacana/internal/config"
)

func resourceCfg() config.Resolved {
	return config.Resolved{
		ID:      "test",
		Disable: map[string]bool{},
		Inspection: config.ResolvedInspection{
			DecompressionRatioLimit: 100,
			MaxMemoryBuffer:        1024, // 1KB
			MaxInspectSize:         128 * 1024,
			EvaluationTimeout:      50 * time.Millisecond,
		},
	}
}

func gzipBytes(data []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

func TestDecompressionRatioBlock(t *testing.T) {
	cfg := resourceCfg()
	cfg.Inspection.DecompressionRatioLimit = 10
	rv := NewResourceValidator(cfg)

	// Create a gzip payload with high ratio (repeated bytes compress well).
	original := bytes.Repeat([]byte("A"), 10000)
	compressed := gzipBytes(original)
	ratio := int64(len(original)) / int64(len(compressed))
	t.Logf("compressed: %d, decompressed: %d, ratio: %d:1", len(compressed), len(original), ratio)

	r := httptest.NewRequest("POST", "/", bytes.NewReader(compressed))
	r.Header.Set("Content-Encoding", "gzip")
	r.ContentLength = int64(len(compressed))

	d := rv.CheckDecompression(context.Background(), r)
	if !d.Block {
		t.Errorf("expected decompression ratio block, got: %+v (ratio=%d)", d, ratio)
	}
}

// TestDecompressionBombIsRefusedWithoutInflatingIt pins that the ratio check
// does not itself decompress the bomb into memory: a ~50KB body that expands
// to 50MB must be refused after reading a few MB and keeping none of them.
func TestDecompressionBombIsRefusedWithoutInflatingIt(t *testing.T) {
	var buf bytes.Buffer
	w, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	zeros := make([]byte, 1<<20)
	for i := 0; i < 50; i++ {
		_, _ = w.Write(zeros)
	}
	_ = w.Close()
	bomb := buf.Bytes()

	rv := NewResourceValidator(resourceCfg()) // ratio limit 100
	r := httptest.NewRequest("POST", "/", bytes.NewReader(bomb))
	r.Header.Set("Content-Encoding", "gzip")
	r.ContentLength = int64(len(bomb))

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	d := rv.CheckDecompression(context.Background(), r)
	runtime.ReadMemStats(&after)

	if !d.Block {
		t.Fatalf("a %d-byte body expanding to 50MB was not refused: %+v", len(bomb), d)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 8<<20 {
		t.Errorf("checking the ratio allocated %d bytes; the bomb was inflated in memory", allocated)
	}
}

func TestDecompressionRatioPass(t *testing.T) {
	cfg := resourceCfg()
	cfg.Inspection.DecompressionRatioLimit = 1000
	rv := NewResourceValidator(cfg)

	original := []byte("small payload")
	compressed := gzipBytes(original)

	r := httptest.NewRequest("POST", "/", bytes.NewReader(compressed))
	r.Header.Set("Content-Encoding", "gzip")
	r.ContentLength = int64(len(compressed))

	d := rv.CheckDecompression(context.Background(), r)
	if d.Block {
		t.Errorf("should pass, got: %+v", d)
	}
}

func TestSpoolBodyFitsInMemory(t *testing.T) {
	cfg := resourceCfg()
	cfg.Inspection.MaxMemoryBuffer = 1024
	rv := NewResourceValidator(cfg)

	body := strings.NewReader("small body")
	r := httptest.NewRequest("POST", "/", body)

	data, cleanup, err := rv.SpoolBody(r)
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "small body" {
		t.Errorf("data = %q", data)
	}
}

func TestSpoolBodySpoolsToDisk(t *testing.T) {
	cfg := resourceCfg()
	cfg.Inspection.MaxMemoryBuffer = 10 // 10 bytes
	rv := NewResourceValidator(cfg)

	bigBody := strings.Repeat("x", 100)
	r := httptest.NewRequest("POST", "/", strings.NewReader(bigBody))

	data, cleanup, err := rv.SpoolBody(r)
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 100 {
		t.Errorf("data length = %d, want 100", len(data))
	}
}

func TestNoBodyDecompression(t *testing.T) {
	rv := NewResourceValidator(resourceCfg())
	r := httptest.NewRequest("GET", "/", nil)
	d := rv.CheckDecompression(context.Background(), r)
	if d.Block {
		t.Error("should not block without body")
	}
}

func TestDecompressionNoEncoding(t *testing.T) {
	rv := NewResourceValidator(resourceCfg())
	r := httptest.NewRequest("POST", "/", strings.NewReader("plain body"))
	d := rv.CheckDecompression(context.Background(), r)
	if d.Block {
		t.Error("should not block without content-encoding")
	}
}

func init() {
	_ = io.Discard // ensure io import compiles
}
