GET {{host}}/conformance/content-types/plain

HTTP 200
[Asserts]
header "Content-Type" startsWith "text/plain"
body contains "plain text body"
