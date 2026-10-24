# With php-php2shell-part-headers disabled, the same
# 4001-header-line multipart part reaches the upstream.
POST {{host}}/upload
Content-Type: multipart/form-data; boundary=BarbacanaShapeBoundary
file,fixtures/header-flood.bin;
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
jsonpath "$.path" == "/upload"
