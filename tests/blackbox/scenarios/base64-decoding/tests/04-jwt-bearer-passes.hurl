# A JWT in Authorization: Bearer must pass — headers are explicitly out
# of scope for the base64-decoding stage. This test fails-loud if a
# regression starts decoding header values.
GET {{host}}/secure
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.fake_signature
HTTP 200
