# Uploading a file exceeding file_size (1KB) is rejected.
POST {{host}}/upload
[MultipartFormData]
file: file,fixtures/large.bin; image/png
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
