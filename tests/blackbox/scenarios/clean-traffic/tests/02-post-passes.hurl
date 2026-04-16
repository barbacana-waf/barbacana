# Clean POST request with JSON body reaches the upstream.
POST {{host}}/users
Content-Type: application/json
{"name": "alice", "role": "admin"}
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
jsonpath "$.path" == "/users"
jsonpath "$.body_size" > 0
