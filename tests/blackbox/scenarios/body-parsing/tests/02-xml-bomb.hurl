# XML with entity expansion exceeding xml_entities (10) is rejected.
POST {{host}}/api/data
Content-Type: application/xml
```
<?xml version="1.0"?>
<!DOCTYPE bomb [
  <!ENTITY x "data">
]>
<root>&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;</root>
```
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
