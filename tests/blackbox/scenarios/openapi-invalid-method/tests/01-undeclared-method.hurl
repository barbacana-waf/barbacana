# DELETE /users is not declared in the OpenAPI spec (only GET).
# The OpenAPI validator returns 404 when a method isn't found for a path.
DELETE {{host}}/users
HTTP 404
