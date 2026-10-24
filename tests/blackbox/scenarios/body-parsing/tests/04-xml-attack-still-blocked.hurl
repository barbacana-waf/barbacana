# Parsing the body as XML must not hide an attack carried in element text.
POST {{host}}/api/data
Content-Type: application/xml
```
<?xml version="1.0"?>
<order><note>1 UNION SELECT password FROM users</note></order>
```
HTTP 403
