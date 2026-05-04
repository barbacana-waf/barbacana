# 933151 matches medium-risk PHP function names followed by `(`.
# `apache_setenv(` is in the allow-list of dangerous-but-not-eval names.
GET {{host}}/test?q=apache_setenv%28
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
