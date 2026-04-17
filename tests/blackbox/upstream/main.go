package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

type echoResponse struct {
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Query    string            `json:"query"`
	Headers  map[string]string `json:"headers"`
	BodySize int               `json:"body_size"`
}

func handler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	headers := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	resp := echoResponse{
		Method:   r.Method,
		Path:     r.URL.Path,
		Query:    r.URL.RawQuery,
		Headers:  headers,
		BodySize: len(body),
	}

	// Set response headers that the WAF should strip.
	w.Header().Set("Server", "MockUpstream/1.0")
	w.Header().Set("X-Powered-By", "Go")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func main() {
	addr := ":19000"
	if v := os.Getenv("UPSTREAM_ADDR"); v != "" {
		addr = v
	}
	fmt.Fprintf(os.Stderr, "upstream listening on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, http.HandlerFunc(handler)))
}
