# JSON nested beyond json_depth (5) is rejected.
POST {{host}}/api/data
Content-Type: application/json
{"a":{"b":{"c":{"d":{"e":{"f":"deep"}}}}}}
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
