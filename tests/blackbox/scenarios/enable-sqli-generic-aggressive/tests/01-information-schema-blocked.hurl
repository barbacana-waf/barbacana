# 942330 matches classic SQLi probes — including the literal
# `information_schema` token via the `[^0-9A-Z_a-z]information_schema`
# arm. A bare `information_schema` reference in an arg is a strong
# fingerprint of recon and the leaf opt-in flags it explicitly.
GET {{host}}/test?q=%20information_schema
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
