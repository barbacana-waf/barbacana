# Cache-control story. The moderate response-header preset injects a
# restrictive Cache-Control by default — this test documents whether
# Barbacana respects the upstream's explicit caching directives or
# overrides them. If it overrides, that's a finding to be triaged
# against the cache-control header protection, not a test bug.
GET {{host}}/conformance/cache

HTTP 200
[Asserts]
header "ETag" == "\"abc123\""
header "Cache-Control" == "public, max-age=3600"
header "Vary" contains "Accept-Encoding"
header "Last-Modified" exists
