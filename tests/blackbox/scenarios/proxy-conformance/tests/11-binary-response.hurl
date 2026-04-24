# Binary passthrough: a 67-byte PNG. Barbacana must not corrupt the
# bytes, re-encode, or drop the image/png Content-Type.
GET {{host}}/conformance/binary

HTTP 200
[Asserts]
header "Content-Type" == "image/png"
bytes count == 67
bytes startsWith hex,89504e470d0a1a0a;
