# Status 405 must carry the Allow header through.
GET {{host}}/conformance/status/405

HTTP 405
[Asserts]
header "Allow" exists
jsonpath "$.code" == 405
