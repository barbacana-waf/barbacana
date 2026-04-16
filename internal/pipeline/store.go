// Package pipeline provides the Caddy middleware handler that wires all
// barbacana protections into the HTTP request/response path.
package pipeline

import (
	"sync"

	"github.com/barbacana-waf/barbacana/internal/config"
)

var (
	mu       sync.RWMutex
	resolved map[string]*config.Resolved
)

// RegisterConfigs stores the resolved route configs so that the Caddy handler
// module can look them up at provision time. Called by serve.go between
// config.Resolve and caddy.Load.
func RegisterConfigs(routes []config.Resolved) {
	mu.Lock()
	defer mu.Unlock()
	resolved = make(map[string]*config.Resolved, len(routes))
	for i := range routes {
		resolved[routes[i].ID] = &routes[i]
	}
}

// GetConfig returns the resolved config for a route ID.
func GetConfig(id string) *config.Resolved {
	mu.RLock()
	defer mu.RUnlock()
	return resolved[id]
}
