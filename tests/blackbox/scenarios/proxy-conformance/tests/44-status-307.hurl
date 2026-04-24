# Status 307 preserves the method on redirect. Do not follow it here.
GET {{host}}/conformance/status/307
[Options]
location: false

HTTP 307
[Asserts]
header "Location" exists
