# A 100MB upload passes.
POST {{host}}/upload
[MultipartFormData]
title: archive
file: file,fixtures/upload-100mb.txt; text/plain
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
