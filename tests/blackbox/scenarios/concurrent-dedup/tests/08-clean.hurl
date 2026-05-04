# Clean traffic alongside the attacks — verifies the parallel pipeline
# hands non-blocking requests through without contention.
GET {{host}}/test
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
