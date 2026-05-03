# 950100 (response-phase) fires when the upstream emits any 5xx
# status code. With the leaf enabled the response is replaced by the
# WAF block page; the upstream's leaky body never reaches the client.
GET {{host}}/leak/5xx
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
