# 941380 matches AngularJS-style {{ ... }} expressions in args.
GET {{host}}/test?q=%7B%7Bconstructor.constructor%28%27alert%281%29%27%29%28%29%7D%7D
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
