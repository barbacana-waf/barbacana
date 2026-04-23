# CRS 932390 — classic shell fork-bomb shape: name() { expr | expr; }
GET {{host}}/block/?cmd=a()%7Ba%7Ca%3B%7D
HTTP 403
