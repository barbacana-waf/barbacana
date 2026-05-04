# With http-compliance-non-printable-characters enabled, a request
# whose URL contains a byte outside the printable ASCII set trips
# curated rule 920271 (validateByteRange 9,10,13,32-126,128-255).
# %01 (SOH, 0x01) is below 32 and not in the allowlist.
GET {{host}}/test%01
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
