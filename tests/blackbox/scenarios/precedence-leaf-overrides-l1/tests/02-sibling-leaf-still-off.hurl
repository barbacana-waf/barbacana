# Sibling leaf under http-compliance — http-compliance-restricted-headers
# (default On normally, would block X-HTTP-Method-Override via curated
# 920450) — stays off because the L1 disable still wins for it (no
# leaf-level override in the enable list). Hurl can send the otherwise-
# restricted header and the request reaches upstream.
GET {{host}}/test
X-HTTP-Method-Override: PUT
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.headers.X-Http-Method-Override" == "PUT"
