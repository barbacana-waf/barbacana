# Proxy: a clean request is forwarded to the upstream and the response returned
GET http://{{host}}:{{proxy_port}}/index.html
HTTP 200
[Asserts]
body contains "hello from upstream"
