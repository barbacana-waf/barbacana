# Two sequential requests on the same connection must both complete
# successfully. Exercises keep-alive through Barbacana.
GET {{host}}/conformance/connection/alive

HTTP 200
[Asserts]
jsonpath "$.alive" == true

GET {{host}}/conformance/connection/alive

HTTP 200
[Asserts]
jsonpath "$.alive" == true
