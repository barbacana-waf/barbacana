# HTTP Parameter Pollution: same arg name twice. Curated 921170 fills
# tx.paramcounter_id, 921180 fires when any counter > 1.
GET {{host}}/test?id=1&id=2
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
