# XML body round-trips: response body is the echoed XML, envelope in
# the X-Request-Echo header.
POST {{host}}/conformance/content/xml
Content-Type: application/xml
<request><name>test</name></request>

HTTP 200
[Asserts]
header "Content-Type" contains "application/xml"
header "X-Request-Echo" exists
xpath "string(//request/name)" == "test"
