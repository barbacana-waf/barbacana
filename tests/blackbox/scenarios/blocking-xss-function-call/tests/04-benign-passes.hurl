# Benign JS-shaped text — must pass.
GET {{host}}/?q=Object.prototype.toString.call(obj)
HTTP 200
