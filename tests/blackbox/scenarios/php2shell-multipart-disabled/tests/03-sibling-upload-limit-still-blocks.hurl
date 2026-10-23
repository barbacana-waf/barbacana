# Disabling both php-php2shell multipart-shape leaves does not touch the
# file-upload-limits bucket: a restricted-file upload (.htaccess) is
# still blocked by file-upload-limits-executable.
POST {{host}}/upload
Content-Type: multipart/form-data; boundary=BarbacanaShapeBoundary
file,fixtures/htaccess-upload.bin;
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
