# A well-formed XML document with a prolog is parsed as XML and reaches the
# upstream. Read as form data, `<?xml version` was a field name that tripped
# the XSS rules.
POST {{host}}/api/data
Content-Type: application/xml; charset=utf-8
```
<?xml version="1.0" encoding="UTF-8"?>
<order xmlns="urn:example:orders"><id>42</id><note>two coffees &amp; a bagel</note></order>
```
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
