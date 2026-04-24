# HEAD returns the headers a GET would return, but no body.
HEAD {{host}}/conformance/resource/1

HTTP 200
[Asserts]
header "Content-Length" exists
bytes count == 0
