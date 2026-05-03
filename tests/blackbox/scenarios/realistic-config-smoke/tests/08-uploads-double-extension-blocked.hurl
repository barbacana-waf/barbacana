# /uploads/* — double_extension: true on the multipart guard. Filename
# `evil.php.jpg` trips file-upload-limits-double-extension.
POST {{host}}/uploads/avatar
Content-Type: multipart/form-data; boundary=----barbacanaSmoke
```
------barbacanaSmoke
Content-Disposition: form-data; name="file"; filename="evil.php.jpg"
Content-Type: image/jpeg

content
------barbacanaSmoke--
```
HTTP 403
