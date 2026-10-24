# A real WebDAV PROPFIND with an XML body and a Depth header reaches the
# upstream on a route that lists PROPFIND in accept.methods.
PROPFIND {{host}}/dav/files/alice
Content-Type: application/xml; charset=utf-8
Depth: 1
```
<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:"><d:prop><d:getlastmodified/><d:getcontentlength/><d:resourcetype/></d:prop></d:propfind>
```
HTTP 200
[Asserts]
jsonpath "$.method" == "PROPFIND"
jsonpath "$.path" == "/dav/files/alice"
