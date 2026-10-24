# The route without WebDAV methods keeps its allowlist.
PROPFIND {{host}}/hello
Depth: 0
HTTP 405
