# JSON object within the key limit (5) passes through.
POST {{host}}/api/data
Content-Type: application/json
{"k1":"v","k2":"v","k3":"v"}
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
