# In detect-only mode, body exceeding max_body_size (100 bytes) passes through.
POST {{host}}/upload
Content-Type: application/octet-stream
`AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
