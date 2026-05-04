# null-bytes leaf is in the character-encoding bucket. The L2 enable
# (specificity 1) wins over the L1 disable (specificity 0).
GET {{host}}/test%00malicious
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
