# Valid single-file upload with allowed MIME type passes.
POST {{host}}/upload
[MultipartFormData]
file: file,fixtures/valid.png; image/png
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
