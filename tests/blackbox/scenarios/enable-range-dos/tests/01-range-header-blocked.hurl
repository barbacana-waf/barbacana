# 921230 fires on any presence of a Range request header. With the
# leaf enabled the request blocks; the off-by-default state is the
# usual one for browser-style routes that legitimately use ranges.
GET {{host}}/test
Range: bytes=0-100
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
