# Oversized body passes when max-body-size is disabled.
POST {{host}}/data
Content-Type: application/json
{"data": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
