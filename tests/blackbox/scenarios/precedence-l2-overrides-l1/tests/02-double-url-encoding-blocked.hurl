# http-compliance-double-url-encoding is default Off. The L2 bucket
# enable (specificity 1) covers it and flips it ON — even though the
# L1 disable also covers it, the L2 wins on specificity. Native
# protocol.DoubleEncode now fires on `%252f` in the query.
GET {{host}}/page?redirect=%252fhome
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
