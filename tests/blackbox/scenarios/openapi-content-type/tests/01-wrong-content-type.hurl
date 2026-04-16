# POST with XML content-type to JSON-only endpoint is rejected.
POST {{host}}/items
Content-Type: application/xml
<item><name>test</name></item>
HTTP 415
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.error" exists
