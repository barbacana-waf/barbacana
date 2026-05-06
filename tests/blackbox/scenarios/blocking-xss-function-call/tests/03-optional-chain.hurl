# Optional-chaining call on a dangerous global — blocked by 210003.
GET {{host}}/?q=alert%3F.(document.cookie)
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
