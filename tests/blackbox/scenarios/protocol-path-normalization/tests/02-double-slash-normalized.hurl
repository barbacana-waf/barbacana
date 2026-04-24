# Doubled slashes must reach the upstream exactly as the client sent
# them. Barbacana normalizes the path only for CRS inspection; r.URL
# is not mutated, so the reverse proxy forwards `//api//users`
# unchanged. The mock upstream delegates to Go's http.ServeMux, which
# answers a non-canonical request path with a 307 redirect to its
# clean form — that 307 is the signal that Barbacana did NOT rewrite
# the path on its way to the upstream.
#
# See docs/design/conventions.md §"Normalization is for detection,
# not for proxying".
GET {{host}}//api//users
HTTP 307
[Asserts]
header "Location" exists
