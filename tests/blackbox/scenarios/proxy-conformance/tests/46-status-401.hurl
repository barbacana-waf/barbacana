# Status 401 must carry WWW-Authenticate through to the client.
GET {{host}}/conformance/status/401

HTTP 401
[Asserts]
header "WWW-Authenticate" exists
jsonpath "$.code" == 401
