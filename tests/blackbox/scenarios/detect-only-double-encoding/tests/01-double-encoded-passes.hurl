# In detect-only mode, double-encoded query param passes through to upstream.
# Query strings are not normalized by Caddy, so %252f reaches the WAF handler as-is.
# The double-encoding is detected but not blocked (logged only).
GET {{host}}/page?redirect=%252fhome
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
