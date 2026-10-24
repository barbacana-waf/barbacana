# Attacks in JSON values are found per key.
POST {{host}}/api/data
Content-Type: application/json
{"user": {"name": "x", "bio": "1 UNION SELECT password FROM users"}}
HTTP 403
