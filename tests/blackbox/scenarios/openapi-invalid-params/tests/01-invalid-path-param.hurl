# Path parameter /users/{id} requires an integer; sending a string is rejected.
GET {{host}}/users/not-an-integer
HTTP 422
