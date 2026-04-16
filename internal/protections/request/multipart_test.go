package request

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/barbacana-waf/barbacana/internal/config"
)

func multipartCfg() config.Resolved {
	return config.Resolved{
		ID:      "test",
		Disable: map[string]bool{},
		Multipart: config.ResolvedMultipart{
			FileLimit:       10,
			FileSize:        10 * 1024 * 1024,
			AllowedTypes:    []string{},
			DoubleExtension: true,
		},
		RunMultipartParser: true,
		Inspection: config.ResolvedInspection{
			EvaluationTimeout: 50 * time.Millisecond,
		},
	}
}

func createMultipartBody(files map[string]string) (*bytes.Buffer, string) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	for name, content := range files {
		part, _ := writer.CreateFormFile("file", name)
		part.Write([]byte(content))
	}
	writer.Close()
	return body, writer.FormDataContentType()
}

func TestMultipartFileCount(t *testing.T) {
	cfg := multipartCfg()
	cfg.Multipart.FileLimit = 2
	mv := NewMultipartValidator(cfg)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	for i := 0; i < 5; i++ {
		part, _ := writer.CreateFormFile("file", fmt.Sprintf("file%d.txt", i))
		part.Write([]byte("content"))
	}
	writer.Close()

	r := httptest.NewRequest("POST", "/upload", body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	d := mv.Validate(context.Background(), r)
	if !d.Block || d.Protection != MultipartFileLimit {
		t.Errorf("expected file count block, got: %+v", d)
	}
}

func TestMultipartDoubleExtension(t *testing.T) {
	cfg := multipartCfg()
	mv := NewMultipartValidator(cfg)

	body, ct := createMultipartBody(map[string]string{"shell.php.jpg": "evil"})
	r := httptest.NewRequest("POST", "/upload", body)
	r.Header.Set("Content-Type", ct)
	d := mv.Validate(context.Background(), r)
	if !d.Block || d.Protection != MultipartDoubleExtension {
		t.Errorf("expected double extension block, got: %+v", d)
	}
}

func TestMultipartDoubleExtensionClean(t *testing.T) {
	cfg := multipartCfg()
	mv := NewMultipartValidator(cfg)

	body, ct := createMultipartBody(map[string]string{"photo.jpg": "image data"})
	r := httptest.NewRequest("POST", "/upload", body)
	r.Header.Set("Content-Type", ct)
	d := mv.Validate(context.Background(), r)
	if d.Block {
		t.Errorf("clean file should pass, got: %+v", d)
	}
}

func TestMultipartAllowedTypes(t *testing.T) {
	cfg := multipartCfg()
	cfg.Multipart.AllowedTypes = []string{"image/png", "image/jpeg"}
	mv := NewMultipartValidator(cfg)

	body, ct := createMultipartBody(map[string]string{"doc.pdf": "pdf content"})
	r := httptest.NewRequest("POST", "/upload", body)
	r.Header.Set("Content-Type", ct)
	d := mv.Validate(context.Background(), r)
	// The part type defaults to application/octet-stream or guessed from ext.
	// PDF won't match image/png or image/jpeg so should be blocked.
	if !d.Block || d.Protection != MultipartAllowedTypes {
		t.Errorf("expected type block, got: %+v", d)
	}
}

func TestMultipartNotMultipartRoute(t *testing.T) {
	cfg := multipartCfg()
	cfg.RunMultipartParser = false
	mv := NewMultipartValidator(cfg)

	body, ct := createMultipartBody(map[string]string{"shell.php.jpg": "evil"})
	r := httptest.NewRequest("POST", "/upload", body)
	r.Header.Set("Content-Type", ct)
	d := mv.Validate(context.Background(), r)
	if d.Block {
		t.Error("should skip multipart validation when parser disabled")
	}
}

func TestHasDoubleExtension(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"file.txt", false},
		{"file.php.jpg", true},
		{"file.exe.pdf", true},
		{"file.tar.gz", false}, // tar.gz is not risky
		{"shell.PHP.jpg", true},
		{"file", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hasDoubleExtension(tc.name)
			if got != tc.want {
				t.Errorf("hasDoubleExtension(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func init() {
	_ = strings.TrimSpace // prevent unused import
}
