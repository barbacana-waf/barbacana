# Liveness: process is alive and reachable
GET http://{{host}}:{{health_port}}/healthz
HTTP 200
[Asserts]
body == "ok"

# Readiness: process has finished initialization and is ready to serve traffic
GET http://{{host}}:{{health_port}}/readyz
HTTP 200
[Asserts]
body == "ok"
