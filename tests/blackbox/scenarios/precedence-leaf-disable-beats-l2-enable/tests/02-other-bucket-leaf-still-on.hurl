# Sibling leaf in the same bucket — http-compliance-null-bytes (default
# On) — has no leaf-level override, so the L2 enable confirms it ON
# (no-op promotion since it was already On). Null byte still blocks.
GET {{host}}/test%00malicious
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
