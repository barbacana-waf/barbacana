# 956110 (response-phase) matches `<%= … %>` and `#{ … }` shapes in
# response bodies — fingerprints of unrendered Ruby/ERB source leaking
# through. /leak/ruby returns "<%= 7*7 %>" so the rule fires.
GET {{host}}/leak/ruby
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
