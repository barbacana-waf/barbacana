# Multipart POST carrying PHP's PHP_SESSION_UPLOAD_PROGRESS field — the
# CVE-2026-109619 ("PHP2Shell") request vector — is blocked by
# php-php2shell-session-upload-progress. The field value is an inert token; this proves
# the WAF rule fires on the request shape, nothing more.
POST {{host}}/upload
[MultipartFormData]
PHP_SESSION_UPLOAD_PROGRESS: 123
comment: hello
HTTP 403
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
jsonpath "$.request_id" != ""
