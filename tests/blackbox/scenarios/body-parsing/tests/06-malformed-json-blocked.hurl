# A body that is not valid JSON under a JSON Content-Type would produce no
# parsed fields for the rules to inspect, so it is blocked outright.
POST {{host}}/api/data
Content-Type: application/json
```
{"user": "x", "bio": "1 UNION SELECT password FROM users"
```
HTTP 403
