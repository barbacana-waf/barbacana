# 942130 matches `<word> = <word>` shapes where both words capture-
# back-reference to each other — the boolean-tautology probe (1=1,
# admin=admin). Chained: TX:1 @streq TX:2 confirms the two captures
# match before scoring.
GET {{host}}/test?q=1%3D1
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
