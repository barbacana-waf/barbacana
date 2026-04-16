# Clean class name parameter passes through without blocking.
GET {{host}}/api
[QueryStringParams]
class: UserService
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
