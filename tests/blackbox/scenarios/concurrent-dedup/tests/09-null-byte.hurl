# Null byte path — http-compliance-null-bytes (native + CRS 920270).
# Both detectors fire on the same leaf ID; the auditCollector must
# record it exactly once.
GET {{host}}/test%00malicious
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
