# Catch-all route inherits the global enable list. command-injection-
# english-words is opt-in at the global level, so a "cat /etc/passwd"
# arg trips curated 932236 anywhere it lands — including the catch-all.
GET {{host}}/anywhere?cmd=cat%20/etc/passwd
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
