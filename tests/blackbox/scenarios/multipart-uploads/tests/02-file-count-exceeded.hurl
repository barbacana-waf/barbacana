# Uploading 3 files when file_limit is 2 is rejected.
POST {{host}}/upload
[MultipartFormData]
file1: file,fixtures/valid.png; image/png
file2: file,fixtures/valid.png; image/png
file3: file,fixtures/valid.png; image/png
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
