# 944300 matches base64-encoded fragments of dangerous Java class
# names — Runtime, ProcessBuilder, etc. Payload: `cHJvY2Vzc2J1aWxkZXI=`
# is base64("processbuilder") and the regex matches the
# `HJv(?:Y2Vzc2J1aWxkZXI...` arm.
GET {{host}}/test?p=cHJvY2Vzc2J1aWxkZXI%3D
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
