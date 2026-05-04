# /api/* — accept.content_types: [application/json] is enforced;
# text/plain bodies on POST are rejected.
POST {{host}}/api/users
Content-Type: text/plain
```
hello world
```
HTTP 415
