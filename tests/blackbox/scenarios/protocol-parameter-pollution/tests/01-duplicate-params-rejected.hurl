# Duplicate query parameters are rejected when parameter_pollution is set to reject.
GET {{host}}/search?q=normal&q=duplicate
HTTP 403
