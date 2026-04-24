# Deeply-nested path must survive proxying with no segment collapsing.
GET {{host}}/conformance/path/segments/with/many/levels

HTTP 200
[Asserts]
jsonpath "$._request.path" == "/conformance/path/segments/with/many/levels"
