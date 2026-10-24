# A classic HTML form post.
POST {{host}}/login
Content-Type: application/x-www-form-urlencoded
[FormParams]
username: alice
password: correct horse battery staple
remember: on
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
