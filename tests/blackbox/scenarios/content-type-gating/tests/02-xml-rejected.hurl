# POST with text/xml is rejected when only application/json is accepted.
POST {{host}}/api/data
Content-Type: text/xml
<root><data>test</data></root>
HTTP 415
