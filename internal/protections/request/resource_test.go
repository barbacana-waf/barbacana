package request

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http/httptest"
	"strings"
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

	_, d := rv.CheckDecompression(context.Background(), r)
	if !d.Block {
		t.Errorf("expected decompression ratio block, got: %+v (ratio=%d)", d, ratio)
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

	decompressed, d := rv.CheckDecompression(context.Background(), r)
	if d.Block {
		t.Errorf("should pass, got: %+v", d)
	}
	if string(decompressed) != "small payload" {
		t.Errorf("decompressed = %q", decompressed)
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
	_, d := rv.CheckDecompression(context.Background(), r)
	if d.Block {
		t.Error("should not block without body")
	}
}

func TestDecompressionNoEncoding(t *testing.T) {
	rv := NewResourceValidator(resourceCfg())
	r := httptest.NewRequest("POST", "/", strings.NewReader("plain body"))
	_, d := rv.CheckDecompression(context.Background(), r)
	if d.Block {
		t.Error("should not block without content-encoding")
	}
}

func init() {
	_ = io.Discard // ensure io import compiles
}
