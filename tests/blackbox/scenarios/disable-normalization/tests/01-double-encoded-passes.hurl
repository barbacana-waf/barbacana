# When double-encoding protection is disabled, double-encoded query param passes through.
# Query strings are not normalized by Caddy, so %252f reaches the WAF handler as-is.
GET {{host}}/page?redirect=%252fhome
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
