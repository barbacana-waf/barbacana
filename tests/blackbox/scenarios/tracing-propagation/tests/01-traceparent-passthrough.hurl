# A client-supplied W3C traceparent header reaches the upstream unchanged
# when tracing is disabled. The mock upstream (tests/blackbox/upstream)
# echoes incoming headers as JSON, so we assert the trace-id portion of
# the propagated header matches what was sent.
#
# Header shape: 00-<32 hex trace-id>-<16 hex span-id>-<2 hex flags>.
GET {{host}}/echo
traceparent: 00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01
HTTP 200
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.headers.Traceparent" exists
# The trace-id (positions 4..36) must survive the WAF transparently.
jsonpath "$.headers.Traceparent" contains "0102030405060708090a0b0c0d0e0f10"
