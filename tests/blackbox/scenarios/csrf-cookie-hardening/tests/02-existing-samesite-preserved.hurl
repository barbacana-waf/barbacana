# Default route: upstream's explicit SameSite=Strict choice must be
# left alone — Barbacana never overrides an upstream-set attribute.
GET {{host}}/default/csrf/set-cookie-with-samesite
HTTP 200
[Asserts]
cookie "session" == "abc123"
cookie "session[SameSite]" == "Strict"
