# Gzip body with compression ratio exceeding limit (10:1) is rejected.
POST {{host}}/api/data
Content-Encoding: gzip
Content-Type: application/octet-stream
file,fixtures/bomb.gz;
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
