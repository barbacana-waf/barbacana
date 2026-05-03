# 942430 fires when an arg contains 12+ special characters in a row
# (anomaly heuristic). Payload below is 14 distinct meta-chars.
GET {{host}}/test?q=%21%40%23%24%25%5E%26%2A%28%29_%2B-%3D%7B%7D%5B%5D
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
