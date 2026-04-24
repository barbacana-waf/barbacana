# HEAD returns the same headers as GET but no body.
HEAD {{host}}/conformance/head

HTTP 200
[Asserts]
header "Content-Length" exists
header "Content-Type" contains "application/json"
bytes count == 0
