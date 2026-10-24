# Expect: 100-continue is what curl sends for larger uploads. It is not an
# attack and must not be blocked.
POST {{host}}/hello
Content-Type: application/json
Expect: 100-continue
{"name": "alice"}
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
