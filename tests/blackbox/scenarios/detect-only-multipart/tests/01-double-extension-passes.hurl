# In detect-only mode, double-extension filename (shell.php.jpg) passes through.
POST {{host}}/upload
[MultipartFormData]
file: file,fixtures/shell.php.jpg; image/jpeg
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
