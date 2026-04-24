# Chunked response with zero payload bytes must still deliver a 200.
GET {{host}}/conformance/encoding/empty-chunked

HTTP 200
