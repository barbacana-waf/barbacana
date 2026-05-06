# With base64-decoding-path disabled, the encoded SQLi segment stays
# opaque to CRS and the request reaches the upstream.
GET {{host}}/JyBPUiAxPTEtLQ==/users
HTTP 200
