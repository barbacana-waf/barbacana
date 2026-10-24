# 21 empty file controls (filename="") with nested field names — the
# empty-file-control vector of CVE-2026-109618 ("PHP2Shell") — are blocked
# by php-php2shell-empty-file-controls.
POST {{host}}/upload
Content-Type: multipart/form-data; boundary=BarbacanaShapeBoundary
file,fixtures/empty-file-controls.bin;
HTTP 403
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
jsonpath "$.request_id" != ""
