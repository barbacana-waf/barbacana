# 932190 matches path-glob shapes used to evade command filters:
# `/something*` or `/?something`. Encoded `?` in the value below
# triggers the `[/-9A-Z_a-z]+\?` arm of the regex.
GET {{host}}/test?cmd=/etc/p%3Fsswd
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
