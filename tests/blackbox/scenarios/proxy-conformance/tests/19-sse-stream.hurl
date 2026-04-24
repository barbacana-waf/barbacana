# Server-sent events: Content-Type and at least one data: frame must
# reach the client. Barbacana must not buffer so long that the stream
# is effectively broken, nor strip the event-stream content-type.
GET {{host}}/conformance/sse

HTTP 200
[Asserts]
header "Content-Type" contains "text/event-stream"
body contains "data:"
