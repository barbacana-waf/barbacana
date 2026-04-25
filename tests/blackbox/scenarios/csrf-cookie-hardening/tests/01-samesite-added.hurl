# Default route: upstream returns a bare Set-Cookie. Barbacana must
# add SameSite=Lax while preserving the original name and value.
GET {{host}}/default/csrf/set-cookie
HTTP 200
[Asserts]
cookie "session" == "abc123"
cookie "session[SameSite]" == "Lax"
cookie "session[Path]" == "/"
