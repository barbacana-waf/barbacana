# SMTP command injection via query parameter. Matches CRS rule 932300
# (curated PL2). The value contains the literal 4-char sequence \r\n
# (backslash-r-backslash-n, URL-encoded as %5Cr%5Cn) so it does not
# trigger the protocol-level crlf-injection check — only CRS's
# t:escapeSeqDecode converts it to a real CRLF before matching.
#
# At the PL1 baseline this payload would pass; the curated set promotes
# rule 932300 to always-on so the request is blocked by
# rce-mail-protocol-injection.
GET {{host}}/search?to=%5Cr%5CnRCPT%20TO%3A%3Ca%40b.c%3E
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
