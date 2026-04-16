# Double extension passes when multipart-double-extension is disabled.
POST {{host}}/upload
[MultipartFormData]
file: file,fixtures/shell.php.jpg; image/jpeg
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
