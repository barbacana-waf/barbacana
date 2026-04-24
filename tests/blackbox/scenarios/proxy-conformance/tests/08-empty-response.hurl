# 204 No Content from upstream must arrive as 204 with no body.
GET {{host}}/conformance/empty

HTTP 204
[Asserts]
bytes count == 0
