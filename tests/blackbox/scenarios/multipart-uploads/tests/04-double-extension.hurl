# Double-extension filename (shell.php.jpg) is rejected.
POST {{host}}/upload
[MultipartFormData]
file: file,fixtures/shell.php.jpg; image/jpeg
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
