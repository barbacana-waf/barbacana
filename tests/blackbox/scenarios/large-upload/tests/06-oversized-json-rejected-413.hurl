# A non-multipart body over the window is rejected with 413 by default.
POST {{host}}/api/data
Content-Type: application/json
file,fixtures/big.json;
HTTP 413
