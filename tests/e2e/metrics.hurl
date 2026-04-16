# Observability: metrics endpoint is reachable and contains the expected series
GET http://{{host}}:{{metrics_port}}/metrics
HTTP 200
[Asserts]
# Prometheus text format
header "Content-Type" contains "text/plain"
# barbacana build metadata is always present
body contains "waf_build_info{"
# standard Go runtime metrics are always present
body contains "go_goroutines "
body contains "go_memstats_alloc_bytes "
