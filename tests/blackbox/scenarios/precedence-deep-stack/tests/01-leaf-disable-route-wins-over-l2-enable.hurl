# Route leaf-disable (spec 2, layer 1) is more specific than the
# global L2 enable (spec 1, layer 0), so http-compliance-double-url-
# encoding stays OFF. Encoded `%252f` reaches upstream.
GET {{host}}/page?redirect=%252fhome
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
