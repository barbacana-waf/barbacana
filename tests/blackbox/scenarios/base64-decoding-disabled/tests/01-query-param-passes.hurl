# With base64-decoding-parameters disabled, the encoded SQLi value
# stays opaque to CRS and the request reaches the upstream.
GET {{host}}/login?q=JyBPUiAxPTEtLQ==
HTTP 200
