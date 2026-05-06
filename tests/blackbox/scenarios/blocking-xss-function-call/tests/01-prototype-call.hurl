# Function.prototype.call/apply/bind invocation on a dangerous global —
# blocked by Barbacana custom rule 210001.
GET {{host}}/?q=alert.apply(null,%5B1%5D)
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
