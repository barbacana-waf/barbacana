# PUT must reach the upstream as PUT — no silent method coercion.
PUT {{host}}/conformance/echo
Content-Type: application/json
{"key":"value"}

HTTP 200
[Asserts]
jsonpath "$.method" == "PUT"
jsonpath "$.path" == "/conformance/echo"
