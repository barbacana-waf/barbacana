# Same upstream as test 01 but on a route with response-error-masking
# disabled — the original stack trace must reach the client untouched.
GET {{host}}/disabled/error/stack-trace
HTTP 500
[Asserts]
body contains "panic:"
body contains "goroutine"
