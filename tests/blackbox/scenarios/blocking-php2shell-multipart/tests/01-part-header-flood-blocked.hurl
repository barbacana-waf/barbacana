# A multipart part carrying 4001 header lines — the header-flood vector of
# CVE-2026-109618 ("PHP2Shell") — is blocked by
# php-php2shell-part-headers. The body is ~40KB, far under
# any byte-size cap: only a header count catches it.
POST {{host}}/upload
Content-Type: multipart/form-data; boundary=BarbacanaShapeBoundary
file,fixtures/header-flood.bin;
HTTP 403
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
jsonpath "$.request_id" != ""
