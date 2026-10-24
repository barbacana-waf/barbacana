# MKCOL, COPY and MOVE (the latter two carry Destination and Overwrite).
MKCOL {{host}}/dav/files/alice/photos
HTTP 200
[Asserts]
jsonpath "$.method" == "MKCOL"

COPY {{host}}/dav/files/alice/a.txt
Destination: {{host}}/dav/files/alice/b.txt
Overwrite: F
HTTP 200
[Asserts]
jsonpath "$.method" == "COPY"

MOVE {{host}}/dav/files/alice/b.txt
Destination: {{host}}/dav/files/alice/c.txt
HTTP 200
[Asserts]
jsonpath "$.method" == "MOVE"
