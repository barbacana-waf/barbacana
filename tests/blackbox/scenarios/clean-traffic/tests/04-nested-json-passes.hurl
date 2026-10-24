# Nested JSON with arrays, numbers, booleans and null.
POST {{host}}/orders
Content-Type: application/json
{"order": {"id": 42, "items": [{"sku": "A-1", "qty": 2}, {"sku": "B-7", "qty": 1}], "gift": false, "note": null}}
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
