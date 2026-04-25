# No Origin, no Referer, no CORS on the route — typical curl/webhook
# call. The check has no allow-list to compare against and falls
# through to allow.
POST {{host}}/no-cors/echo
Content-Type: application/json
`{"ok":true}`
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
