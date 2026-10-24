# The form around a large upload is still inspected.
POST {{host}}/upload
[MultipartFormData]
q: 1 UNION SELECT password FROM users
file: file,fixtures/upload-5mb.txt; text/plain
HTTP 403
