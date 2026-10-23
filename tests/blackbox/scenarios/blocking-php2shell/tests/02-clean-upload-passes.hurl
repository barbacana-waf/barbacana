# Ordinary multipart upload (text field + file part, no upload-progress
# marker) passes with php-php2shell-session-upload-progress enabled.
POST {{host}}/upload
[MultipartFormData]
comment: profile notes
attachment: file,fixtures/notes.txt; text/plain
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
jsonpath "$.path" == "/upload"
