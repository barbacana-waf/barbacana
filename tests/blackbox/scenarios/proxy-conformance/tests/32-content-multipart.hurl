# multipart/form-data with a text field and a small file.
POST {{host}}/conformance/content/multipart
[MultipartFormData]
note: hello
attachment: file,fixtures/multipart-sample.txt; text/plain

HTTP 200
[Asserts]
jsonpath "$._request.method" == "POST"
jsonpath "$._request.content_type" contains "multipart/form-data"
jsonpath "$.fields.note" == "hello"
jsonpath "$.files.attachment.filename" == "multipart-sample.txt"
