# SQL injection payload in POST body.
POST {{host}}/api/data
[FormParams]
username: admin
password: ' OR ''='
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
