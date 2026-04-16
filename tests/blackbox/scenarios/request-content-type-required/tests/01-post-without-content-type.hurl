# POST without Content-Type is rejected.
POST {{host}}/data
```
some body content
```
HTTP 415
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.error" exists
