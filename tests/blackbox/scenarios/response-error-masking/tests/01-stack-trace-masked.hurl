# Upstream returns a 500 with a Go panic + goroutine trace. Barbacana
# must replace the body with the generic JSON envelope while
# preserving the original 500 status code.
GET {{host}}/default/error/stack-trace
HTTP 500
[Asserts]
header "Content-Type" contains "application/json"
body contains "An unexpected error occurred"
body contains "request_id"
body not contains "panic:"
body not contains "goroutine"
body not contains "main.go"
