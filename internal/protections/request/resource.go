package request

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/metrics"
	"github.com/barbacana-waf/barbacana/internal/protections"
)

const (
	DecompressionRatioLimit = "decompression-ratio-limit"
	MaxMemoryBuffer         = "max-memory-buffer"
	MaxInspectionSize       = "max-inspection-size"
)

// ResourceValidator checks resource-limit protections.
type ResourceValidator struct {
	cfg config.Resolved
}

func NewResourceValidator(cfg config.Resolved) *ResourceValidator {
	return &ResourceValidator{cfg: cfg}
}

// CheckDecompression reads a compressed body, checks the decompression ratio,
// and returns the decompressed bytes. Returns a blocking decision if the
// ratio exceeds the limit.
func (rv *ResourceValidator) CheckDecompression(ctx context.Context, r *http.Request) ([]byte, protections.Decision) {
	if protections.IsDisabled(DecompressionRatioLimit, rv.cfg.Disable) {
		return nil, protections.Allow()
	}

	enc := strings.ToLower(r.Header.Get("Content-Encoding"))
	if enc != "gzip" && enc != "deflate" {
		return nil, protections.Allow()
	}

	if r.Body == nil {
		return nil, protections.Allow()
	}

	compressedBody, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, protections.Allow()
	}
	compressedSize := int64(len(compressedBody))
	if compressedSize == 0 {
		return compressedBody, protections.Allow()
	}

	var reader io.ReadCloser
	switch enc {
	case "gzip":
		reader, err = gzip.NewReader(bytes.NewReader(compressedBody))
		if err != nil {
			return compressedBody, protections.Allow()
		}
	case "deflate":
		reader = flate.NewReader(bytes.NewReader(compressedBody))
	}
	defer func() { _ = reader.Close() }()

	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return compressedBody, protections.Allow()
	}
	decompressedSize := int64(len(decompressed))

	ratio := decompressedSize / compressedSize
	if int(ratio) > rv.cfg.Inspection.DecompressionRatioLimit {
		return nil, protections.Decision{
			Block: true, Protection: DecompressionRatioLimit,
			Reason: fmt.Sprintf("decompression ratio %d:1 exceeds limit %d:1",
				ratio, rv.cfg.Inspection.DecompressionRatioLimit),
		}
	}

	return decompressed, protections.Allow()
}

// SpoolBody reads the body, keeping the first maxMemoryBuffer bytes in RAM
// and spooling the rest to a temp file. Returns the combined reader and a
// cleanup function. The caller must call cleanup when done.
func (rv *ResourceValidator) SpoolBody(r *http.Request) ([]byte, func(), error) {
	if r.Body == nil {
		return nil, func() {}, nil
	}

	maxMem := rv.cfg.Inspection.MaxMemoryBuffer

	// Read up to maxMem into memory.
	buf := make([]byte, 0, maxMem)
	lr := io.LimitReader(r.Body, maxMem)
	memBytes, err := io.ReadAll(lr)
	if err != nil {
		return nil, func() {}, err
	}
	buf = append(buf, memBytes...)

	// Check if there's more data.
	extra := make([]byte, 1)
	n, err := r.Body.Read(extra)
	if n == 0 || err == io.EOF {
		// Everything fit in memory.
		return buf, func() {}, nil
	}

	// Spool remainder to disk.
	metrics.BodySpooledTotal.WithLabelValues(rv.cfg.ID).Inc()
	tmpFile, err := os.CreateTemp("", "barbacana-body-*")
	if err != nil {
		return buf, func() {}, err
	}
	if _, err := tmpFile.Write(extra[:n]); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return buf, func() {}, err
	}
	if _, err := io.Copy(tmpFile, r.Body); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return buf, func() {}, err
	}
	_ = tmpFile.Close()

	// Read back from disk for inspection (only first maxInspectSize).
	diskData, _ := os.ReadFile(tmpFile.Name())
	combined := append(buf, diskData...)

	cleanup := func() {
		_ = os.Remove(tmpFile.Name())
	}
	return combined, cleanup, nil
}

