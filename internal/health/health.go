// Package health exposes /healthz and /readyz HTTP handlers served by a
// standalone net/http server on HealthListen. They sit outside the
// protection pipeline intentionally (architecture.md §"What lives
// outside this pipeline"). Readiness will gain real state tracking
// once the config compiler and CRS loader can report it.
package health

import (
	"net/http"
)

const (
	HealthzPath = "/healthz"
	ReadyzPath  = "/readyz"
)

// Handler returns a ServeMux with the two endpoints registered.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(HealthzPath, ok)
	mux.HandleFunc(ReadyzPath, ok)
	return mux
}

func ok(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}
