package health

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerEndpoints(t *testing.T) {
	h := Handler()

	cases := []struct {
		name string
		path string
	}{
		{name: "healthz", path: HealthzPath},
		{name: "readyz", path: ReadyzPath},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)

			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", rec.Code)
			}
			body, _ := io.ReadAll(rec.Body)
			if strings.TrimSpace(string(body)) != "ok" {
				t.Errorf("body = %q, want %q", string(body), "ok")
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
				t.Errorf("Content-Type = %q, want text/plain prefix", ct)
			}
		})
	}
}

func TestHandlerUnknownPath404(t *testing.T) {
	h := Handler()
	r := httptest.NewRequest(http.MethodGet, "/not-a-real-path", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}
