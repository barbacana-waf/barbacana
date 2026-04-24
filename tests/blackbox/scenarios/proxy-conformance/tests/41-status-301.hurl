# Status 301 with Location must pass through. Do not follow the redirect.
GET {{host}}/conformance/status/301
[Options]
location: false

HTTP 301
[Asserts]
header "Location" exists
