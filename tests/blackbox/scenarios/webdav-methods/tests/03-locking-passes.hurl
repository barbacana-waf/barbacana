# LOCK, then a write that presents the lock token in If, then UNLOCK with
# Lock-Token. A route that accepts LOCK/UNLOCK must let these headers through.
LOCK {{host}}/dav/files/alice/a.txt
Content-Type: application/xml; charset=utf-8
Timeout: Second-3600
```
<?xml version="1.0" encoding="UTF-8"?>
<d:lockinfo xmlns:d="DAV:"><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype></d:lockinfo>
```
HTTP 200
[Asserts]
jsonpath "$.method" == "LOCK"

PUT {{host}}/dav/files/alice/a.json
Content-Type: application/json
If: (<opaquelocktoken:00000000-0000-0000-0000-000000000000>)
{"ok": true}
HTTP 200
[Asserts]
jsonpath "$.method" == "PUT"

UNLOCK {{host}}/dav/files/alice/a.txt
Lock-Token: <opaquelocktoken:00000000-0000-0000-0000-000000000000>
HTTP 200
[Asserts]
jsonpath "$.method" == "UNLOCK"
