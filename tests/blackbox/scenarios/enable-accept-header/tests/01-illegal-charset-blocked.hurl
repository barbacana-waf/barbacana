# With http-compliance-accept-header enabled, an Accept header carrying
# an unsupported charset parameter trips CRS rule 920600 (CRITICAL,
# PL1) and blocks. The leaf is off by default because many legitimate
# clients omit Accept entirely; users opt in when their app expects
# strict browser-style Accept semantics.
GET {{host}}/test
Accept: text/html;charset=bogus-1234
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
