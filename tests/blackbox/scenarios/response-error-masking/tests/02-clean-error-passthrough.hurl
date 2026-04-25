# A well-behaved upstream JSON error has no framework markers, so the
# body must pass through unmodified — the masker is for stack traces,
# not for application-level error envelopes.
GET {{host}}/default/error/clean-json
HTTP 500
[Asserts]
body contains "internal server error"
