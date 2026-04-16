# Multipart body with _charset_ field (global charset injection) is blocked by CRS 922xxx.
POST {{host}}/upload
[MultipartFormData]
_charset_: utf-7
data: harmless content
HTTP 403
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
jsonpath "$.request_id" != ""
