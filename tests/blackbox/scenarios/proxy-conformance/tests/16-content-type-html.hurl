GET {{host}}/conformance/content-types/html

HTTP 200
[Asserts]
header "Content-Type" startsWith "text/html"
body contains "<html"
