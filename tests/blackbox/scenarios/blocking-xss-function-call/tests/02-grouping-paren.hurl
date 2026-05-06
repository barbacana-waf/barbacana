# Grouping-paren evasion of token-boundary detectors — blocked by 210002.
GET {{host}}/?q=(alert)(1)
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
