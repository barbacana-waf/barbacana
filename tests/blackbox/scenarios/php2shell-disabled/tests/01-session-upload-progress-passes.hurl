# With php-php2shell-session-upload-progress disabled, the same multipart POST carrying
# the PHP_SESSION_UPLOAD_PROGRESS field reaches the upstream.
POST {{host}}/upload
[MultipartFormData]
PHP_SESSION_UPLOAD_PROGRESS: 123
comment: hello
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
jsonpath "$.path" == "/upload"
