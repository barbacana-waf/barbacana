# CRS 932220 — shell pipe + unix command argument. The variant chosen hits
# only PL2/PL3 rules in sub-protection rce-unix-command; non-curated PL2/PL3
# siblings stay dormant at PL1, so 932220 is the only rule that fires and
# the disable pair passes cleanly.
GET {{host}}/block/?cmd=x%7Ccat%20abc
HTTP 403
