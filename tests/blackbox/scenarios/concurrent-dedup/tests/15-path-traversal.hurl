# Path traversal — local-file-access-dot-dot-paths (native + CRS 930xx
# rules in REQUEST-930). Native PathNorm normalizes; CRS detects the
# raw `../` sequences. Dedup keeps the leaf to a single entry.
GET {{host}}/page?file=../../../../etc/passwd
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
