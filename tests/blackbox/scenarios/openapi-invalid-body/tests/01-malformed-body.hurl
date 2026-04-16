# POST /users with body missing required "name" field.
POST {{host}}/users
Content-Type: application/json
{"age": "not-a-number"}
HTTP 422
