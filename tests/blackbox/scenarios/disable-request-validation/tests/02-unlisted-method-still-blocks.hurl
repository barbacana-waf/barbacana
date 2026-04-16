# Unlisted method still blocks (only max-body-size disabled).
PATCH {{host}}/data
Content-Type: application/json
{"key": "value"}
HTTP 405
[Asserts]
jsonpath "$.error" exists
