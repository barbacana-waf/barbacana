# 942200 matches comment/space-obfuscated SQLi shapes inside JSON args.
# A JSON body containing a SELECT … FROM payload trips the
# `[^0-9A-Z_a-z]select.+[^0-9A-Z_a-z]*?from` arm of the regex.
POST {{host}}/test
Content-Type: application/json
{"q":"1 union select user from passwords"}
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
