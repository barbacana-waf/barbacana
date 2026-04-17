# Clean request passes through with web-shell and data-leakage-ruby disabled.
# Proves the new response-phase category names are accepted by config validation.
GET {{host}}/api/users
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/api/users"
