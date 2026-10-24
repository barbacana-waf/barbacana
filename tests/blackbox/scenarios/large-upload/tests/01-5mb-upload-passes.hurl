# A 5MB upload is far over the 128KB inspection window and must still pass:
# the window counts what the rules read, and they do not read file contents.
POST {{host}}/upload
[MultipartFormData]
title: holiday photos
file: file,fixtures/upload-5mb.txt; text/plain
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
