# Upstream sleeps 2s before responding. Default upstream_timeout is 30s,
# so Barbacana must wait without tearing down the connection.
GET {{host}}/conformance/slow

HTTP 200
[Asserts]
jsonpath "$.message" == "slow but valid"
