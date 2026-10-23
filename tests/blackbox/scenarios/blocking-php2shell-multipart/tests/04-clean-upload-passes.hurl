# Ordinary multipart upload (text field + file part) passes with both
# CVE-2026-109618 multipart-shape leaves enabled.
POST {{host}}/upload
[MultipartFormData]
comment: profile notes
attachment: file,fixtures/notes.txt; text/plain
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
jsonpath "$.path" == "/upload"
