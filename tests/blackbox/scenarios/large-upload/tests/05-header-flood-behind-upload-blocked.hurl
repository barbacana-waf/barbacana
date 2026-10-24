# A part header block past the parser limit, after a 2MB upload.
POST {{host}}/upload
Content-Type: multipart/form-data; boundary=BarbacanaShapeBoundary
file,fixtures/upload-then-header-flood.bin;
HTTP 403
