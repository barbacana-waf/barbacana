# Leaves under a different L1 (http-attacks) are not touched by the
# http-compliance family disable — CRLF injection still blocks at the
# baseline default-on state.
GET {{host}}/test%0d%0aInjected-Header:%20value
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
