# Route enable beats global disable on equal specificity (both leaf-
# level). http-compliance-double-url-encoding is ON for this route;
# the encoded `%252f` triggers native protocol.DoubleEncode → 403.
GET {{host}}/page?redirect=%252fhome
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
