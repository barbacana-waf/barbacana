# Leaf-level disable (specificity 2) beats the L2 enable (specificity 1).
# Double-encoded query passes upstream — native protocol.DoubleEncode is
# off because the leaf disable wins, even though the bucket enable
# would otherwise have flipped this default-Off leaf to ON.
GET {{host}}/page?redirect=%252fhome
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
