# Following the relative redirect re-enters the WAF at /conformance/echo
# and must resolve end-to-end to a 200 from the echo endpoint.
GET {{host}}/conformance/redirect-relative
[Options]
location: true

HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/conformance/echo"
