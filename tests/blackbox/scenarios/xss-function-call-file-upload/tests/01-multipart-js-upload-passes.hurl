# Uploading a .js file via multipart/form-data must pass even when its
# body contains every shape the new XSS rules catch — `alert.call(...)`,
# `confirm.apply(...)`, `eval.bind(...)`, `(alert)(1)`, and
# `alert?.(...)`. Coraza puts file-part bodies in FILES/FILES_TMP_NAMES,
# which the new rules deliberately do not scan, so legitimate JS file
# uploads are never affected. Pinning this contract here so a future
# Coraza change in multipart parsing can't silently start blocking
# real uploads.
POST {{host}}/upload
[MultipartFormData]
file: file,fixtures/script.js; application/javascript
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
jsonpath "$.path" == "/upload"
