# XML within the depth limit (3) passes through.
POST {{host}}/api/data
Content-Type: application/xml
<root><item>value</item></root>
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
