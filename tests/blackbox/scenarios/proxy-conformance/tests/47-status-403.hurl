# Status 403 from the upstream must arrive as 403 (not swallowed
# or rewritten by Barbacana).
GET {{host}}/conformance/status/403

HTTP 403
[Asserts]
jsonpath "$.code" == 403
