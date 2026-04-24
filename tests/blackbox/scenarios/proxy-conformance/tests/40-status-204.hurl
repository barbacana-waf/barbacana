# Status 204 must arrive with no body.
GET {{host}}/conformance/status/204

HTTP 204
[Asserts]
bytes count == 0
