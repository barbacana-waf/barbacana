# Three Set-Cookie headers, each with different attributes, must all
# arrive at the client with values and attributes intact.
GET {{host}}/conformance/set-cookie

HTTP 200
[Asserts]
header "Set-Cookie" count == 3
cookie "session" == "abc123"
cookie "session[Path]" == "/"
cookie "prefs" == "dark"
cookie "prefs[Max-Age]" == 86400
cookie "prefs[Path]" == "/"
cookie "tracking" == "xyz"
cookie "tracking[Domain]" == ".example.com"
cookie "tracking[Path]" == "/"
