# Request with empty Host header is rejected.
GET {{host}}/test
Host:
HTTP 400
