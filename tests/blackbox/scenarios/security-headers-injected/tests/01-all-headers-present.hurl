# All 11 security headers are injected with default values.
GET {{host}}/test
HTTP 200
[Asserts]
header "Strict-Transport-Security" == "max-age=63072000; includeSubDomains"
header "Content-Security-Policy" == "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests"
header "X-Frame-Options" == "DENY"
header "X-Content-Type-Options" == "nosniff"
header "Referrer-Policy" == "strict-origin-when-cross-origin"
header "X-Dns-Prefetch-Control" == "off"
header "Cross-Origin-Opener-Policy" == "same-origin"
header "Cross-Origin-Embedder-Policy" == "unsafe-none"
header "Cross-Origin-Resource-Policy" == "same-origin"
header "Permissions-Policy" == "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()"
header "Cache-Control" == "no-store, no-cache, must-revalidate, max-age=0"
