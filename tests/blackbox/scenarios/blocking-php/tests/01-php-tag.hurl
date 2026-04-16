# PHP injection via inline PHP tags in query parameter.
GET {{host}}/search
[QueryStringParams]
q: <?php system('id'); ?>
HTTP 403
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
jsonpath "$.request_id" != ""
