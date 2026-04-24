# DELETE returns 204 No Content. No body, no envelope.
DELETE {{host}}/conformance/resource/1

HTTP 204
[Asserts]
bytes count == 0
