# Ordinary XML, with the prolog every serializer writes, must reach the
# upstream. This was blocked as XSS for as long as bodies were read as forms.
POST {{host}}/orders
Content-Type: application/xml
```
<?xml version="1.0" encoding="UTF-8"?>
<order><id>42</id><customer>Alice</customer><items><item sku="A-1" qty="2"/></items></order>
```
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
