# Status 302 with Location must pass through. Do not follow the redirect.
GET {{host}}/conformance/status/302
[Options]
location: false

HTTP 302
[Asserts]
header "Location" exists
