# Leaf re-enabled via specificity-2 directive overriding the
# specificity-0 family disable. Null byte in path → 403.
GET {{host}}/test%00malicious
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
