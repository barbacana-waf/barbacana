# http-compliance-null-bytes is default On in the same bucket the
# global L2 enable covers. No leaf-level directive overrides it, so
# the L2 enable carries the leaf to ON (no-op promotion since it was
# already On). Null byte still blocks.
GET {{host}}/test%00malicious
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
