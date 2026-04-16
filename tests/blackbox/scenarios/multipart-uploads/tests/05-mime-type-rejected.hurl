# Uploading a file with disallowed MIME type (text/plain) is rejected.
POST {{host}}/upload
[MultipartFormData]
file: file,fixtures/test.txt; text/plain
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
