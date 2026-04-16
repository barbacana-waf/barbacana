# In detect-only mode, scanner user-agent passes through.
GET {{host}}/
User-Agent: sqlmap/1.0-dev
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
