# Double-encoded query param (%252fhome = encoded %2f + home) is rejected by the double-encoding protection.
# Query strings are not normalized by Caddy, so the raw %252f reaches the WAF handler.
GET {{host}}/page?redirect=%252fhome
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
