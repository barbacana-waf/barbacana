# 932200 matches shell-substitution evasion shapes: $(cmd), backticks,
# wildcard-after-slash, etc. Chained rule — secondary chains check that
# MATCHED_VARS contains both `/` and whitespace, and the predicate's
# `\$[!#\$\(\*\-0-9\?-\[_a-\{]` arm matches `$(`.
GET {{host}}/test?cmd=%24%28ls%20/tmp%29
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
