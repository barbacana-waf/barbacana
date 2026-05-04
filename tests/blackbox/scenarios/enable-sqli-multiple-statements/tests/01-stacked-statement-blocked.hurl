# 942210 detects chained statements — `;<keyword>` after a SQL fragment.
# Payload uses the `[#;]\s*?(?:alter|drop|insert|update)` arm: a `;`
# followed by `drop` token.
GET {{host}}/test?q=1%3B%20drop%20table%20users
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
