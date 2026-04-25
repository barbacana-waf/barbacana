# 200 response that happens to contain "panic:" / "goroutine" tokens
# (e.g. a docs page about Go panics). The masker only inspects 4xx
# and 5xx responses — 2xx must always flow through verbatim.
GET {{host}}/default/error/success-with-trace
HTTP 200
[Asserts]
body contains "panic:"
body contains "goroutine"
