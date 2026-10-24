# 21 empty file controls after a 2MB upload: the upload does not hide them.
POST {{host}}/upload
Content-Type: multipart/form-data; boundary=BarbacanaShapeBoundary
file,fixtures/upload-then-empty-controls.bin;
HTTP 403
