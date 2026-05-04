# With http-compliance-user-agent-header enabled, a request without a
# User-Agent header trips curated rule 920320 and blocks. Hurl always
# sets a User-Agent unless told otherwise; the explicit empty value
# below triggers User-Agent: (empty) which 920320 also rejects via the
# `&REQUEST_HEADERS:User-Agent @eq 0` check on count.
GET {{host}}/test
User-Agent:
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
