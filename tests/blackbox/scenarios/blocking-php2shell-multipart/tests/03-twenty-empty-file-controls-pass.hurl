# Exactly 20 empty file controls — at the limit, not over it — pass.
POST {{host}}/upload
Content-Type: multipart/form-data; boundary=BarbacanaShapeBoundary
file,fixtures/twenty-empty-file-controls.bin;
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
jsonpath "$.path" == "/upload"
