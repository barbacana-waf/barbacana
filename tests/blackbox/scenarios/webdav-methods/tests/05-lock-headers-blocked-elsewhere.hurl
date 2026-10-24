# Lock-Token and If stay restricted on a route that does not accept LOCK.
POST {{host}}/hello
Content-Type: application/json
Lock-Token: <opaquelocktoken:00000000-0000-0000-0000-000000000000>
{"a": 1}
HTTP 403
