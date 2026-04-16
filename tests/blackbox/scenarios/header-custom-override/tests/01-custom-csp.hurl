# Custom CSP value from config overrides the default.
GET {{host}}/test
HTTP 200
[Asserts]
header "Content-Security-Policy" == "default-src 'none'"
