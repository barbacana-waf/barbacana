# With php-php2shell-empty-file-controls disabled, the same
# 21 empty file controls reach the upstream.
POST {{host}}/upload
Content-Type: multipart/form-data; boundary=BarbacanaShapeBoundary
file,fixtures/empty-file-controls.bin;
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
jsonpath "$.path" == "/upload"
