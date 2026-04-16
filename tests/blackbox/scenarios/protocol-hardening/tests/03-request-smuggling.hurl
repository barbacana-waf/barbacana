# Request with Transfer-Encoding header is detected as potential smuggling.
# Hurl cannot send conflicting CL+TE headers; this tests that TE alone
# on a POST with a body triggers the smuggling check when CL is also present.
POST {{host}}/test
Transfer-Encoding: chunked
Content-Type: text/plain
```
hello
```
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
