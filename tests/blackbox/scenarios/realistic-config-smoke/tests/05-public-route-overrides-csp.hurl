# /public/* — route inject sets CSP and COEP=require-corp directly.
GET {{host}}/public/index.html
HTTP 200
[Asserts]
header "Content-Security-Policy" == "default-src 'self'; script-src 'self' 'unsafe-inline'"
header "Cross-Origin-Embedder-Policy" == "require-corp"
