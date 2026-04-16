# HTTP response splitting attack via CRLF in query parameter (CRS 921xxx / native crlf-injection).
# %0d%0a in a redirect destination injects headers into the response — a classic protocol attack.
GET {{host}}/redirect?dest=http://example.com%0d%0aX-Injected:%20evil
HTTP 403
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
jsonpath "$.request_id" != ""
