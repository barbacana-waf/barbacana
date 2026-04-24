# Status 304 Not Modified: no body.
GET {{host}}/conformance/status/304

HTTP 304
[Asserts]
bytes count == 0
