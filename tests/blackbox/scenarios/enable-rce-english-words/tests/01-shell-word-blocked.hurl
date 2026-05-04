# 932236 matches Unix command words at line/word boundaries. Off by
# default because the same regex flags ordinary English text ("echo",
# "find", "make") — opt in only when the route does not accept free
# text in arguments.
GET {{host}}/test?cmd=cat%20/etc/passwd
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
