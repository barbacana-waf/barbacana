package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Compile turns the validated Config into the JSON blob Caddy consumes.
// Caddy owns only the proxy server; /healthz and /metrics are served by
// plain net/http servers bound to HealthListen and MetricsListen. That
// separation is intentional — Caddy's metrics handler uses an isolated
// registry that would not see barbacana's metrics registered via
// prometheus/client_golang's default registerer.
//
// A8 emits a minimal middleware chain: reverse_proxy only, with path
// rewriting if configured. Protection handlers slot in during Phase B.
func Compile(c *Config, resolved []Resolved) ([]byte, error) {
	servers := map[string]any{
		"proxy": proxyServer(c, resolved),
	}

	root := map[string]any{
		"admin": map[string]any{"disabled": true},
		"logging": map[string]any{
			"logs": map[string]any{
				"default": map[string]any{
					"level":   "INFO",
					"encoder": map[string]any{"format": "json"},
				},
			},
		},
		"apps": map[string]any{
			"http": map[string]any{
				"servers": servers,
			},
		},
	}

	out, err := json.Marshal(root)
	if err != nil {
		return nil, fmt.Errorf("marshal caddy json: %w", err)
	}
	return out, nil
}

func proxyServer(c *Config, resolved []Resolved) map[string]any {
	routes := make([]map[string]any, 0, len(c.Routes))
	for i, r := range c.Routes {
		// Use the resolved route ID (which handles auto-generation from paths).
		routeID := r.ID
		if i < len(resolved) {
			routeID = resolved[i].ID
		}
		cr, err := compileRoute(r, routeID)
		if err != nil {
			// Validation has already run; an error here is a programming bug.
			panic(err)
		}
		routes = append(routes, cr)
	}
	server := map[string]any{
		"listen": []string{c.Listen},
		"routes": routes,
	}

	// Slow-request protection: header read timeout.
	if c.Global.Protocol.SlowRequestHeaderTimeout != "" {
		server["read_header_timeout"] = c.Global.Protocol.SlowRequestHeaderTimeout
	}

	// HTTP/2 hardening.
	if c.Global.Protocol.HTTP2MaxConcurrentStreams != nil ||
		c.Global.Protocol.HTTP2MaxDecodedHeaderBytes != nil {
		h2 := map[string]any{}
		if c.Global.Protocol.HTTP2MaxConcurrentStreams != nil {
			h2["max_concurrent_streams"] = *c.Global.Protocol.HTTP2MaxConcurrentStreams
		}
		if c.Global.Protocol.HTTP2MaxDecodedHeaderBytes != nil {
			h2["max_header_list_size"] = *c.Global.Protocol.HTTP2MaxDecodedHeaderBytes
		}
		server["protocols"] = []string{"h1", "h2", "h2c"}
	}

	return server
}

func compileRoute(r Route, routeID string) (map[string]any, error) {
	u, err := url.Parse(r.Upstream)
	if err != nil {
		return nil, fmt.Errorf("route %q upstream: %w", r.ID, err)
	}

	handle := []map[string]any{}

	// Path rewriting: strip_prefix → add_prefix → path (full override).
	// Rewrites run before the barbacana handler so OpenAPI validates
	// against the rewritten path (architecture.md middleware ordering).
	if r.Rewrite != nil {
		if r.Rewrite.Path != "" {
			handle = append(handle, map[string]any{
				"handler": "rewrite",
				"uri":     r.Rewrite.Path,
			})
		} else {
			if r.Rewrite.StripPrefix != "" {
				handle = append(handle, map[string]any{
					"handler":           "rewrite",
					"strip_path_prefix": r.Rewrite.StripPrefix,
				})
			}
			if r.Rewrite.AddPrefix != "" {
				handle = append(handle, map[string]any{
					"handler": "rewrite",
					"uri":     r.Rewrite.AddPrefix + "{http.request.uri}",
				})
			}
		}
	}

	// Barbacana protection handler: runs all protections before the proxy.
	// The handler looks up the resolved config from the pipeline store by
	// route ID. Registered during serve startup, before caddy.Load.
	handle = append(handle, map[string]any{
		"handler":  "barbacana",
		"route_id": routeID,
	})

	upstream := map[string]any{"dial": u.Host}
	proxy := map[string]any{
		"handler":   "reverse_proxy",
		"upstreams": []map[string]any{upstream},
	}
	handle = append(handle, proxy)

	route := map[string]any{"handle": handle}

	if r.Match != nil {
		matcher := map[string]any{}
		if len(r.Match.Hosts) > 0 {
			matcher["host"] = r.Match.Hosts
		}
		if len(r.Match.Paths) > 0 {
			matcher["path"] = r.Match.Paths
		}
		if len(matcher) > 0 {
			route["match"] = []map[string]any{matcher}
		}
	}
	return route, nil
}

// Compact returns a single-line JSON representation of the compiled config
// suitable for `barbacana debug render-config`. A8 ships Compile; the CLI
// wrapper arrives in C4.
func Compact(b []byte) string {
	return strings.TrimSpace(string(b))
}
