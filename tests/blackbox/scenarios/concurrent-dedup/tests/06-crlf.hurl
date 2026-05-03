# CRLF in path — http-attacks-header-crlf-injection (native + CRS 921140).
# Both detectors fire; the leaf is recorded once per request.
GET {{host}}/test%0d%0aInjected:%20value
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
