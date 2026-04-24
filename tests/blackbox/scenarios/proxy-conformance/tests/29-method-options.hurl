# OPTIONS on a collection exposes the Allow header.
OPTIONS {{host}}/conformance/resource

HTTP 204
[Asserts]
header "Allow" contains "GET"
header "Allow" contains "PUT"
header "Allow" contains "DELETE"
