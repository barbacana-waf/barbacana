# 934180 matches SSTI shapes: {%...%} (Jinja/Django) and <%=...%> (ERB).
GET {{host}}/test?q=%3C%25%3D7%2A7%25%3E
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
