# Route leaf-enable on a default-Off leaf flips it ON. The L2 enable
# would also have flipped it (no contradiction), but the route leaf
# entry is the unambiguous most-specific directive. Curated rule
# 920271 (validateByteRange) catches a non-printable byte in the URL.
GET {{host}}/test%01malicious
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
