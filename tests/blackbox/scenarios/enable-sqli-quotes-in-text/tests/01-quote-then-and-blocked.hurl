# 942521 anchors at start of arg, expects a single quote (or `"`,
# backtick) and then a word-token captured into TX:1. Chained rule
# requires TX:1 ∈ {and, or} for the rule to score. Payload: `' or`.
# (`'a' or` would capture TX:1=`a`, fail the chain, and not block.)
GET {{host}}/test?q=%27%20or
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
