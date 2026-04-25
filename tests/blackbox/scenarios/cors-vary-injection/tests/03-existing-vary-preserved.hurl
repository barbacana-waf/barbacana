# Upstream already sets Vary: Accept-Encoding, Accept-Language. The
# CORS-related values must be appended without dropping the existing
# entries — caches need every dimension that affects the body.
GET {{host}}/cors/conformance/cache
HTTP 200
[Asserts]
header "Vary" contains "Accept-Encoding"
header "Vary" contains "Origin"
