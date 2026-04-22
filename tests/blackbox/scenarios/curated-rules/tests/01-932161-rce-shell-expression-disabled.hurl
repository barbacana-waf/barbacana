# Same 932161 payload reaches a route where rce-unix-shell-expression is disabled.
GET {{host}}/allow-rce-shell-expression/
User-Agent: Mozilla/5.0 bin/nslookup
HTTP 200
