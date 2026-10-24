# External entities in an XML body are blocked: with the body parsed as XML,
# no CRS rule reads the DOCTYPE, so xml-parsing-external-entities covers it.
POST {{host}}/api/data
Content-Type: application/xml
```
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>
```
HTTP 403
