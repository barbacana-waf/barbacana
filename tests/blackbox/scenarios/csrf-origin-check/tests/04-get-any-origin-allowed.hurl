# GET is a safe method per RFC 9110 §9.2.1; csrf-origin-check never
# inspects safe methods even when Origin says cross-origin.
GET {{host}}/api/echo
Origin: http://evil.com
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
