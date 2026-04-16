# Exceeding max_header_count (15) triggers rejection.
GET {{host}}/test
X-H1: a
X-H2: b
X-H3: c
X-H4: d
X-H5: e
X-H6: f
X-H7: g
X-H8: h
X-H9: i
X-H10: j
X-H11: k
X-H12: l
X-H13: m
X-H14: n
X-H15: o
X-H16: p
HTTP 431
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.error" exists
