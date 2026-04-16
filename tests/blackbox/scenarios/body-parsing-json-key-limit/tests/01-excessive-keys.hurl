# JSON object with more keys than json_keys limit (5) is rejected.
POST {{host}}/api/data
Content-Type: application/json
{"k1":"v","k2":"v","k3":"v","k4":"v","k5":"v","k6":"v"}
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
