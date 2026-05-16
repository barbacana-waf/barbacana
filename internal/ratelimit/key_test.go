package ratelimit

import (
	"net/http/httptest"
	"testing"
)

func TestIPExtractor_StripsPort(t *testing.T) {
	cases := []struct {
		remoteAddr string
		want       string
	}{
		{"1.2.3.4:5678", "1.2.3.4"},
		{"[::1]:9000", "::1"},
		{"192.168.0.1:443", "192.168.0.1"},
		// No port — returned as-is (e.g. Unix socket path).
		{"192.168.0.1", "192.168.0.1"},
	}
	e := IPExtractor{}
	for _, tc := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remoteAddr
		got, err := e.Extract(r)
		if err != nil {
			t.Errorf("RemoteAddr=%q: unexpected error: %v", tc.remoteAddr, err)
			continue
		}
		if got != tc.want {
			t.Errorf("RemoteAddr=%q: got %q, want %q", tc.remoteAddr, got, tc.want)
		}
	}
}

func TestHeaderExtractor_ReturnsHeader(t *testing.T) {
	e := HeaderExtractor{Header: "CF-Connecting-IP"}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("CF-Connecting-IP", "10.0.0.1")
	r.RemoteAddr = "172.16.0.1:1234"

	got, err := e.Extract(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "10.0.0.1" {
		t.Errorf("got %q, want %q", got, "10.0.0.1")
	}
}

func TestHeaderExtractor_FallsBackToRemoteAddr(t *testing.T) {
	e := HeaderExtractor{Header: "CF-Connecting-IP"}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "172.16.0.5:9000"
	// Header is absent — must fall back to the client IP.

	got, err := e.Extract(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "172.16.0.5" {
		t.Errorf("got %q, want %q", got, "172.16.0.5")
	}
}
