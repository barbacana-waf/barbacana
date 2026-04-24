# Real request smuggling requires conflicting Content-Length and
# Transfer-Encoding headers on the same request. Go's http.Server
# rejects such a request at parse time, so it never reaches a
# handler — meaning the Smuggling protection cannot be exercised
# from hurl. Coverage for that path lives in Go integration tests.
#
# This file verifies the inverse: a POST with only Transfer-Encoding:
# chunked must pass through unblocked. Before Barbacana disabled
# CRS rule 920420 (global content-type allowlist), this case was
# being blocked 403 by CRS — a false positive on text/plain bodies
# that disagreed with Barbacana's per-route accept.content_types.
POST {{host}}/test
Transfer-Encoding: chunked
Content-Type: text/plain
```
hello
```
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
