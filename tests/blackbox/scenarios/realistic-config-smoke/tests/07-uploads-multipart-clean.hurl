# /uploads/* — clean multipart with one file under the size limit
# passes through.
POST {{host}}/uploads/avatar
Content-Type: multipart/form-data; boundary=----barbacanaSmoke
```
------barbacanaSmoke
Content-Disposition: form-data; name="file"; filename="picture.jpg"
Content-Type: image/jpeg

binary-image-bytes-would-go-here
------barbacanaSmoke--
```
HTTP 200
