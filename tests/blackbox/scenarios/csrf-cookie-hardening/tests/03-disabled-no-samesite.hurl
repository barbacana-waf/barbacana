# Disabled route: csrf-samesite-cookies is in the disable list, so
# Barbacana must forward the upstream Set-Cookie unchanged.
GET {{host}}/disabled/csrf/set-cookie
HTTP 200
[Asserts]
cookie "session" == "abc123"
cookie "session[SameSite]" not exists
