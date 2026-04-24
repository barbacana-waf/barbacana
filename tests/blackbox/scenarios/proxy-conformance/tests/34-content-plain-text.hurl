# text/plain body echoed verbatim; envelope in X-Request-Echo header.
# Body encoded as base64 so hurl's parser doesn't mistake the prose for
# a new request line. Decoded payload: "Hello, this is plain text." (26 bytes).
POST {{host}}/conformance/content/plain
Content-Type: text/plain
base64,SGVsbG8sIHRoaXMgaXMgcGxhaW4gdGV4dC4=;

HTTP 200
[Asserts]
header "Content-Type" contains "text/plain"
header "X-Request-Echo" exists
bytes count == 26
