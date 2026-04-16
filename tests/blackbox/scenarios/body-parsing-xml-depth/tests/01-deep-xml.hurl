# XML nested deeper than xml_depth limit (3) is rejected.
POST {{host}}/api/data
Content-Type: application/xml
<a><b><c><d>too deep</d></c></b></a>
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
