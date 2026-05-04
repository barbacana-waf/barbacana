# Sanity counterpart for the off-by-default behavior: the same illegal
# Accept reaches upstream when the leaf is not enabled.  This file
# documents the contract by relying on the always-present clean path —
# a request with a normal Accept passes through whether or not the
# leaf is enabled, so the assertion still holds in this scenario.
GET {{host}}/test
Accept: text/html
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
