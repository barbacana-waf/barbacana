# Same for XML whose tags do not match.
POST {{host}}/api/data
Content-Type: application/xml
```
<a><b>text</a></b>
```
HTTP 403
