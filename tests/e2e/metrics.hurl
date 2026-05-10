# Observability: metrics endpoint is reachable and contains the expected series.
#
# Caddy's HTTP metrics module (caddy_http_*) initialises lazily on the
# first request through a route — drive one proxy GET before scraping
# so caddy_http_requests_total and the duration histogram exist.

GET http://{{host}}:{{proxy_port}}/index.html
HTTP 200

GET http://{{host}}:{{metrics_port}}/metrics
HTTP 200
[Asserts]
# Prometheus text format
header "Content-Type" contains "text/plain"
# barbacana build metadata is always present
body contains "waf_build_info{"
# resolved per-route mode is exposed as an info gauge
body contains "waf_mode_info{"
# standard Go runtime metrics are always present
body contains "go_goroutines "
body contains "go_memstats_alloc_bytes "
# Caddy HTTP metrics module is enabled and reachable through the same handler
body contains "caddy_http_requests_total{"
body contains "caddy_http_request_duration_seconds_bucket{"
