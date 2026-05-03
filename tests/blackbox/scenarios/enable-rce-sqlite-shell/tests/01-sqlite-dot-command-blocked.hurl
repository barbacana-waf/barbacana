# 932210 matches `;.<sqlite-shell-builtin>` — sqlite REPL dot commands.
# Payload: `;.dump` after a benign value; the leading `;` plus `.dump`
# token triggers the rule's allow-list of sqlite shell builtins.
GET {{host}}/test?cmd=foo%3B.dump
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
