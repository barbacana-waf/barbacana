package protections

func groupLDAPInjection() Group {
	return Group{
		ID:          "ldap-injection",
		Name:        "LDAP injection",
		Description: "LDAP injection patterns. Promoted to its own L1 from the original protocol-attack-ldap-injection — it's its own attack class, not an HTTP attack.",
		WhyDisable:  "Safe to disable when no LDAP backend exists.",
		Leaves: []Leaf{
			{ID: "ldap-injection", Default: On, CWE: []int{90}, RuleIDs: []string{"921200"},
				WhatItDoes: "LDAP injection patterns in inputs — *)(uid=*), *))%00, etc.",
				WhyDisable: "Disable if no LDAP backend exists."},
		},
	}
}

func groupMailProtocolInjection() Group {
	return Group{
		ID:          "mail-protocol-injection",
		Name:        "Mail protocol injection",
		Description: "SMTP / IMAP / POP3 protocol-command injection in mail-handling endpoints. Promoted to its own L1 from the original rce-mail-protocol-injection.",
		WhyDisable:  "Safe to disable when your app doesn't process or forward mail headers.",
		Leaves: []Leaf{
			{ID: "mail-protocol-injection", Default: On, CWE: []int{93, 77}, RuleIDs: []string{"932300", "932301", "932310", "932311", "932320", "932321"},
				WhatItDoes: "SMTP / IMAP / POP3 protocol-command injection patterns — \\r\\nMAIL FROM, \\nDATA, etc. injected into email-handling inputs.",
				WhyDisable: "Disable if your app doesn't process or forward mail headers."},
		},
	}
}

func groupTemplateInjection() Group {
	return Group{
		ID:          "template-injection",
		Name:        "Template injection",
		Description: "Server-side template injection (SSTI) detection.",
		WhyDisable:  "Off by default; enable on routes that render server-side templates with user-controlled data.",
		Leaves: []Leaf{
			{ID: "template-injection", Default: Off, CWE: []int{94, 1336}, RuleIDs: []string{"934180"},
				WhatItDoes: "Detects SSTI payloads — {{7*7}}, ${{, <%= template expressions appearing in inputs. Technology-agnostic across template engines.",
				WhyEnable:  "Enable if your app renders server-side templates (Jinja, ERB, Twig, FreeMarker, Velocity, Handlebars) with user-controlled data anywhere in the template. FP risk on routes that legitimately reflect template-syntax-shaped strings."},
		},
	}
}

func groupDataURIAbuse() Group {
	return Group{
		ID:          "data-uri-abuse",
		Name:        "Data URI abuse",
		Description: "data: URI scheme abuse detection.",
		WhyDisable:  "Safe to disable when no data: URI processing happens in the app (most common case).",
		Leaves: []Leaf{
			{ID: "data-uri-abuse", Default: On, CWE: []int{79, 918}, RuleIDs: []string{"934170"},
				WhatItDoes: "Detects data: URI scheme abuse — used in XSS-via-PHP-context, SSRF via fetch APIs, and SVG-injection chains.",
				WhyDisable: "Disable if input legitimately contains data: URIs — for example, a base64-image upload service."},
		},
	}
}

func groupServerDataLeakage() Group {
	return Group{
		ID:          "server-data-leakage",
		Name:        "Server data leakage",
		Description: "Tech-agnostic server-error / info disclosure detection.",
		WhyDisable:  "Safe to disable when custom error pages already mask all server errors.",
		Leaves: []Leaf{
			{ID: "server-data-leakage-directory-listing", Default: On, CWE: []int{548}, RuleIDs: []string{"950130"},
				WhatItDoes: "Detects HTML directory listing patterns in responses (Index of /, <title>Directory Listing</title>).",
				WhyDisable: "Disable if responses legitimately render directory listings — for example, a file-browser app."},
			{ID: "server-data-leakage-cgi-source", Default: On, CWE: []int{540}, RuleIDs: []string{"950140"},
				WhatItDoes: "Detects CGI source-code leakage in responses (#!/usr/bin/perl, cgi-bin paths exposed).",
				WhyDisable: "Disable for routes that intentionally serve CGI scripts. Rare."},
			{ID: "server-data-leakage-aspnet-errors", Default: On, CWE: []int{209}, RuleIDs: []string{"950150"},
				WhatItDoes: "Detects ASP.NET exception leakage in responses (<title>Server Error</title>, [NullReferenceException]).",
				WhyDisable: "Disable if you've already configured custom error pages in ASP.NET."},
			{ID: "server-data-leakage-5xx-bodies", Default: Off, CWE: []int{209}, RuleIDs: []string{"950100"},
				WhatItDoes: "Detects 5xx-status responses for masking.",
				WhyEnable:  "Enable to mask 5xx response bodies via response inspection. Off by default because masking-by-status-code is already provided by response-error-masking."},
		},
	}
}

func groupWebShellDetection() Group {
	return Group{
		ID:          "web-shell-detection",
		Name:        "Web shell detection",
		Description: "Known web-shell signature detection in responses.",
		WhyDisable:  "Safe to disable for read-only static sites with no upload paths.",
		Leaves: []Leaf{
			{ID: "web-shell-detection", Default: On, CWE: []int{912, 94}, RuleIDs: []string{"955100", "955110", "955120", "955130", "955140", "955150", "955160", "955170", "955180", "955190", "955200", "955210", "955220", "955230", "955240", "955250", "955260", "955270", "955280", "955290", "955300", "955310", "955320", "955330", "955340", "955350", "955400"},
				WhatItDoes: "Catches 27 known web-shell signatures in response bodies — r57, WSO, b4tm4n, Mini Shell, Ashiyane, ASP-shells, etc. Single bucket because operators rarely want fine-grained control over which web-shell families are detected.",
				WhyDisable: "Disable if you legitimately serve files that match web-shell signatures — for example, a malware-research repository."},
		},
	}
}

func groupScannerDetection() Group {
	return Group{
		ID:          "scanner-detection",
		Name:        "Scanner detection",
		Description: "Known security-scanner User-Agent detection.",
		WhyDisable:  "Safe to disable when operating behind a CDN that already filters scanner User-Agents.",
		Leaves: []Leaf{
			{ID: "scanner-detection-user-agent", Default: On, CWE: []int{200}, RuleIDs: []string{"913100"},
				WhatItDoes: "Detects User-Agent strings of known vulnerability scanners (sqlmap, nikto, w3af, masscan, nuclei, etc.).",
				WhyDisable: "Disable for routes that serve security tooling itself."},
		},
	}
}

func groupSessionFixation() Group {
	return Group{
		ID:          "session-fixation",
		Name:        "Session fixation",
		Description: "Session-fixation attack detection.",
		WhyDisable:  "Safe to disable when your service is API-only using bearer tokens with no cookie-based sessions.",
		Leaves: []Leaf{
			{ID: "session-fixation-cookie-injection", Default: On, CWE: []int{384}, RuleIDs: []string{"943100"},
				WhatItDoes: "Detects Set-Cookie values being injected via HTML — an attempt to plant a session cookie via an XSS-style payload.",
				WhyDisable: "Rarely worth disabling."},
			{ID: "session-fixation-external-referer", Default: On, CWE: []int{384}, RuleIDs: []string{"943110"},
				WhatItDoes: "Detects session-ID parameters with off-domain Referer headers — fingerprint of an attacker linking to your app with a pre-set session ID.",
				WhyDisable: "Disable if cross-domain session-handoff is intentional — for example, a federated-login flow."},
			{ID: "session-fixation-missing-referer", Default: On, CWE: []int{384}, RuleIDs: []string{"943120"},
				WhatItDoes: "Detects session-ID parameters on requests with no Referer at all — same attack pattern as session-fixation-external-referer, slightly different shape.",
				WhyDisable: "Disable for routes that legitimately receive direct session-ID-bearing links — for example, a magic-link auth flow."},
		},
	}
}

func groupHTTP2() Group {
	return Group{
		ID:          "http2",
		Name:        "HTTP/2",
		Description: "Native HTTP/2 frame-flood and DoS guards.",
		WhyDisable:  "Safe to disable when HTTP/2 is not exposed (HTTP/1.1 only at the listener).",
		Leaves: []Leaf{
			{ID: "http2-frame-flood", Default: On, CWE: []int{400}, RuleIDs: []string{"native"},
				WhatItDoes: "Native HTTP/2 CONTINUATION-frame flood protection (CVE-2024-27316 family).",
				WhyDisable: "Rarely worth disabling."},
			{ID: "http2-header-bomb", Default: On, CWE: []int{400, 409}, RuleIDs: []string{"native"},
				WhatItDoes: "HPACK decompression bomb protection — caps the expansion ratio of HPACK-encoded headers.",
				WhyDisable: "Rarely worth disabling."},
			{ID: "http2-max-streams", Default: On, CWE: []int{400, 770}, RuleIDs: []string{"native"},
				WhatItDoes: "Per-connection HTTP/2 stream-count cap.",
				WhyDisable: "Disable for backends needing many concurrent HTTP/2 streams per connection."},
		},
	}
}

func groupRequestValidation() Group {
	return Group{
		ID:          "request-validation",
		Name:        "Request validation",
		Description: "Native request-shape rules — body/url/header size, allowed methods, required headers, slow-client detection.",
		WhyDisable:  "Risky — disable only when operating in detect-only mode or with a different size-cap layer (CDN, ingress controller) that demonstrably handles these checks.",
		Leaves: []Leaf{
			{ID: "request-validation-max-body-size", Default: On, CWE: []int{400, 770}, RuleIDs: []string{"native"}, Status: 413,
				WhatItDoes: "Maximum request-body size; returns 413 on violation.",
				WhyDisable: "Disable for routes with intentionally large bodies."},
			{ID: "request-validation-max-url-length", Default: On, CWE: []int{400}, RuleIDs: []string{"native"}, Status: 414,
				WhatItDoes: "Maximum URL length; returns 414 on violation.",
				WhyDisable: "Disable for routes with very long URLs — for example, legacy GET-with-many-params APIs."},
			{ID: "request-validation-max-header-size", Default: On, CWE: []int{400}, RuleIDs: []string{"native"}, Status: 431,
				WhatItDoes: "Total header bytes cap; returns 431 on violation.",
				WhyDisable: "Disable for clients sending large auth tokens in headers. Rare."},
			{ID: "request-validation-max-header-count", Default: On, CWE: []int{400}, RuleIDs: []string{"native"}, Status: 431,
				WhatItDoes: "Maximum header count; returns 431 on violation.",
				WhyDisable: "Disable for clients sending many headers."},
			{ID: "request-validation-argument-limits", Default: On, CWE: []int{400}, RuleIDs: []string{"920360", "920370", "920380", "920390"},
				WhatItDoes: "Argument name/value length, count, and total-size caps.",
				WhyDisable: "Disable for routes accepting genuinely long arg names/values — for example, file metadata APIs."},
			{ID: "request-validation-allowed-methods", Default: On, CWE: []int{749}, RuleIDs: []string{"native"}, Status: 405,
				WhatItDoes: "Method allow-list per route from accept.methods; returns 405 on violation.",
				WhyDisable: "Disable to accept any HTTP method. Usually a security mistake."},
			{ID: "request-validation-require-host-header", Default: On, CWE: []int{20}, RuleIDs: []string{"native"}, Status: 400,
				WhatItDoes: "Host header required; returns 400 on violation.",
				WhyDisable: "Disable for legacy clients without Host header (HTTP/1.0 only)."},
			{ID: "request-validation-require-content-type", Default: On, CWE: []int{20}, RuleIDs: []string{"native"}, Status: 415,
				WhatItDoes: "Content-Type required for POST/PUT/PATCH; returns 415 on violation.",
				WhyDisable: "Disable for routes that accept bodies without content-type. Rare."},
			{ID: "request-validation-slow-clients", Default: On, CWE: []int{400}, RuleIDs: []string{"native"},
				WhatItDoes: "Slow-request DoS protection — drops connections that send headers/body too slowly (Slowloris).",
				WhyDisable: "Disable for environments with slow legitimate clients — for example, low-bandwidth IoT."},
		},
	}
}

func groupJSONParsing() Group {
	return Group{
		ID:          "json-parsing",
		Name:        "JSON parsing",
		Description: "Native JSON body parser limits.",
		WhyDisable:  "Safe to disable when no JSON body parsing happens in this service.",
		Leaves: []Leaf{
			{ID: "json-parsing-max-depth", Default: On, CWE: []int{400, 674}, RuleIDs: []string{"native"},
				WhatItDoes: "JSON nesting-depth cap — defends against parser stack overflow.",
				WhyDisable: "Disable for legitimate deeply-nested JSON — for example, GraphQL queries with many sub-selections."},
			{ID: "json-parsing-max-keys", Default: On, CWE: []int{400, 407}, RuleIDs: []string{"native"},
				WhatItDoes: "Maximum JSON keys per object — defends against hash-collision DoS.",
				WhyDisable: "Disable for JSON bodies with many keys per object."},
		},
	}
}

func groupXMLParsing() Group {
	return Group{
		ID:          "xml-parsing",
		Name:        "XML parsing",
		Description: "Native XML body parser limits.",
		WhyDisable:  "Safe to disable when no XML body parsing happens in this service.",
		Leaves: []Leaf{
			{ID: "xml-parsing-max-depth", Default: On, CWE: []int{400, 674}, RuleIDs: []string{"native"},
				WhatItDoes: "XML nesting-depth cap — defends against parser stack overflow.",
				WhyDisable: "Disable for deeply-nested XML schemas. Rare."},
			{ID: "xml-parsing-entity-expansion", Default: On, CWE: []int{776}, RuleIDs: []string{"native"},
				WhatItDoes: "Billion-laughs / entity-expansion protection — caps the number of <!ENTITY>/<!DOCTYPE> directives in a request body to defend against entity-expansion DoS. XXE-proper (external SYSTEM/PUBLIC entities) is mitigated separately by Go's encoding/xml not resolving external entities; this rule covers expansion-ratio attacks only.",
				WhyDisable: "Rarely worth disabling — billion-laughs is a real threat."},
		},
	}
}

func groupResourceLimits() Group {
	return Group{
		ID:          "resource-limits",
		Name:        "Resource limits",
		Description: "Native resource-limit protections.",
		WhyDisable:  "Risky — disable only on internal services with trusted clients to maximize throughput, with awareness that ReDoS, zip-bombs, and memory exhaustion attacks become more effective.",
		Leaves: []Leaf{
			{ID: "resource-limits-max-inspection-size", Default: On, CWE: []int{400}, RuleIDs: []string{"native"},
				WhatItDoes: "Maximum bytes inspected per request — beyond this size, the body is forwarded without inspection.",
				WhyDisable: "Disable for very-large-body routes where partial inspection isn't acceptable. Better to turn off WAF entirely on those routes."},
			{ID: "resource-limits-max-memory", Default: On, CWE: []int{400, 770}, RuleIDs: []string{"native"},
				WhatItDoes: "In-flight memory budget cap — protects against memory exhaustion under load.",
				WhyDisable: "Rarely worth disabling."},
			{ID: "resource-limits-decompression-ratio", Default: On, CWE: []int{409}, RuleIDs: []string{"native"},
				WhatItDoes: "Decompression-ratio cap on gzip/deflate request bodies — defends against zip-bomb.",
				WhyDisable: "Rarely worth disabling."},
			{ID: "resource-limits-evaluation-timeout", Default: On, CWE: []int{1333, 400}, RuleIDs: []string{"native"},
				WhatItDoes: "Per-request CRS-engine timeout — protects against ReDoS-driven CRS evaluation latency.",
				WhyDisable: "Rarely worth disabling."},
		},
	}
}

func groupOpenAPI() Group {
	return Group{
		ID:          "openapi",
		Name:        "OpenAPI",
		Description: "Native OpenAPI-3 request validation against the route's openapi.spec.",
		WhyDisable:  "Safe to disable when no OpenAPI spec is maintained for this route.",
		Leaves: []Leaf{
			{ID: "openapi-path-not-in-spec", Default: On, CWE: []int{20}, RuleIDs: []string{"native"}, Status: 404,
				WhatItDoes: "Path not in OpenAPI spec; returns 404 on violation.",
				WhyDisable: "Disable for routes intentionally accepting paths not in the spec."},
			{ID: "openapi-method-not-in-spec", Default: On, CWE: []int{749}, RuleIDs: []string{"native"}, Status: 405,
				WhatItDoes: "Method not in spec for the matched path; returns 405 on violation.",
				WhyDisable: "Disable for routes accepting methods not in the spec."},
			{ID: "openapi-parameter-mismatch", Default: On, CWE: []int{20}, RuleIDs: []string{"native"}, Status: 422,
				WhatItDoes: "Parameter shape mismatch (type, required, format); returns 422 on violation.",
				WhyDisable: "Disable for routes with optional query params not declared in the spec."},
			{ID: "openapi-body-mismatch", Default: On, CWE: []int{20}, RuleIDs: []string{"native"}, Status: 422,
				WhatItDoes: "Request body shape mismatch against the spec; returns 422 on violation.",
				WhyDisable: "Disable for routes whose bodies don't match the spec strictly."},
			{ID: "openapi-content-type-not-in-spec", Default: On, CWE: []int{20}, RuleIDs: []string{"native"}, Status: 415,
				WhatItDoes: "Content-Type not declared in the spec for the path/method; returns 415 on violation.",
				WhyDisable: "Disable for routes that accept content types not in the spec."},
		},
	}
}

func groupResponseHeaders() Group {
	return Group{
		ID:          "response-headers",
		Name:        "Response headers",
		Description: "Response-header manipulation — injection of security headers and stripping of leakage headers.",
		WhyDisable:  "Disable carefully when you don't manipulate response headers (handled upstream).",
		Buckets: []L2{
			{
				ID:          "response-headers-add",
				Name:        "Add",
				Description: "Inject security-related response headers. Default policy: headers with safe browser-side defaults that don't visibly break apps stay on. Headers that require per-app tuning to avoid breaking legitimate functionality default off.",
				Leaves: []Leaf{
					{ID: "response-headers-add-hsts", Default: On, CWE: []int{319}, RuleIDs: []string{"native"},
						WhatItDoes: "Inject Strict-Transport-Security header. Low FP risk — almost no app legitimately depends on HTTPS being optional.",
						WhyDisable: "Disable for non-HTTPS deployments."},
					{ID: "response-headers-add-csp", Default: Off, CWE: []int{79, 1021}, RuleIDs: []string{"native"},
						WhatItDoes: "Inject Content-Security-Policy header using the value from route.csp.policy. Primary mitigation against XSS that bypasses output encoding.",
						WhyEnable:  "Off by default because no CSP value strict enough to matter works across apps without per-app tuning — inline scripts, third-party origins, frame ancestors all vary. Enable in conjunction with a route-level csp.policy config field (the directive string the WAF should inject). Without csp.policy set, enabling this leaf is a no-op. Keep off if CSP is configured at the framework layer (Rails, Django middleware)."},
					{ID: "response-headers-add-frame-options", Default: On, CWE: []int{1021}, RuleIDs: []string{"native"},
						WhatItDoes: "Inject X-Frame-Options: SAMEORIGIN to prevent clickjacking.",
						WhyDisable: "Default value is SAMEORIGIN, which is safe for almost every app. Disable for routes intentionally embeddable in iframes — for example, oEmbed providers, payment widgets."},
					{ID: "response-headers-add-nosniff", Default: On, CWE: []int{430, 79}, RuleIDs: []string{"native"},
						WhatItDoes: "Inject X-Content-Type-Options: nosniff to prevent MIME-sniffing attacks.",
						WhyDisable: "Rarely worth disabling — no app legitimately depends on browser MIME sniffing."},
					{ID: "response-headers-add-referrer-policy", Default: On, CWE: []int{200}, RuleIDs: []string{"native"},
						WhatItDoes: "Inject Referrer-Policy header.",
						WhyDisable: "Default value is strict-origin-when-cross-origin (the modern browser default); injecting it explicitly is harmless. Disable if your analytics depends on full-URL referrers."},
					{ID: "response-headers-add-dns-prefetch", Default: On, CWE: []int{200}, RuleIDs: []string{"native"},
						WhatItDoes: "Inject X-DNS-Prefetch-Control header. Minor performance/privacy hint; low FP either way.",
						WhyDisable: "Disable to allow DNS prefetching."},
					{ID: "response-headers-add-coop", Default: Off, CWE: []int{1021}, RuleIDs: []string{"native"},
						WhatItDoes: "Inject Cross-Origin-Opener-Policy header.",
						WhyEnable:  "Enable on routes that need cross-origin window isolation. Off by default because injecting COOP without per-app review breaks OAuth popup flows, embedded windows, and window.opener-using integrations. There's no useful \"safe default\" value — anything strict enough to matter breaks something."},
					{ID: "response-headers-add-coep", Default: Off, CWE: []int{1021}, RuleIDs: []string{"native"},
						WhatItDoes: "Inject Cross-Origin-Embedder-Policy header.",
						WhyEnable:  "Enable on routes that need full cross-origin isolation (e.g., for SharedArrayBuffer). Off by default because COEP requires every cross-origin resource the page loads to opt in via CORP or CORS — most apps would break immediately."},
					{ID: "response-headers-add-corp", Default: Off, CWE: []int{1021}, RuleIDs: []string{"native"},
						WhatItDoes: "Inject Cross-Origin-Resource-Policy header.",
						WhyEnable:  "Enable on routes serving resources that should not be embeddable cross-origin (sensitive APIs, private images). Off by default because the safe default value (cross-origin) provides no protection, and stricter values block legitimate cross-origin embedding."},
					{ID: "response-headers-add-permissions-policy", Default: Off, CWE: []int{1021}, RuleIDs: []string{"native"},
						WhatItDoes: "Inject Permissions-Policy header (formerly Feature-Policy).",
						WhyEnable:  "Enable when you have a tuned policy. Off by default because any policy strict enough to matter blocks legitimate features (camera, microphone, geolocation, USB, payment) and breaks apps that use them — there's no useful one-size-fits-all default."},
					{ID: "response-headers-add-cache-control", Default: Off, CWE: []int{525}, RuleIDs: []string{"native"},
						WhatItDoes: "Inject Cache-Control directives appropriate for the route's sensitivity class.",
						WhyEnable:  "Enable for sensitivity-class-aware cache control on routes you've classified. Off by default because cache policy is route-specific (a static asset, a personalized page, and a sensitive API need three different policies) and is best set at the app or CDN layer."},
				},
			},
			{
				ID:          "response-headers-remove",
				Name:        "Remove",
				Description: "Strip identifying headers from upstream responses.",
				Leaves: []Leaf{
					{ID: "response-headers-remove-server", Default: On, CWE: []int{200}, RuleIDs: []string{"native"},
						WhatItDoes: "Strip Server header from upstream responses.",
						WhyDisable: "Disable if upstream-identification is intentional — for example, debug environments."},
					{ID: "response-headers-remove-powered-by", Default: On, CWE: []int{200}, RuleIDs: []string{"native"},
						WhatItDoes: "Strip X-Powered-By header.",
						WhyDisable: "Rarely worth disabling."},
					{ID: "response-headers-remove-aspnet-version", Default: On, CWE: []int{200}, RuleIDs: []string{"native"},
						WhatItDoes: "Strip X-AspNet-Version and X-AspNetMvc-Version.",
						WhyDisable: "Rarely worth disabling."},
					{ID: "response-headers-remove-generator", Default: On, CWE: []int{200}, RuleIDs: []string{"native"},
						WhatItDoes: "Strip X-Generator header.",
						WhyDisable: "Disable if your CMS depends on the X-Generator header."},
					{ID: "response-headers-remove-drupal", Default: On, CWE: []int{200}, RuleIDs: []string{"native"},
						WhatItDoes: "Strip Drupal-specific headers (X-Drupal-Cache, X-Generator: Drupal …).",
						WhyDisable: "Rarely worth disabling."},
					{ID: "response-headers-remove-varnish", Default: On, CWE: []int{200}, RuleIDs: []string{"native"},
						WhatItDoes: "Strip Varnish-related headers.",
						WhyDisable: "Rarely worth disabling."},
					{ID: "response-headers-remove-via", Default: On, CWE: []int{200}, RuleIDs: []string{"native"},
						WhatItDoes: "Strip Via header.",
						WhyDisable: "Disable if Via is needed for proxy debugging."},
					{ID: "response-headers-remove-runtime", Default: On, CWE: []int{200}, RuleIDs: []string{"native"},
						WhatItDoes: "Strip X-Runtime header (Rails).",
						WhyDisable: "Rarely worth disabling."},
					{ID: "response-headers-remove-debug", Default: On, CWE: []int{200, 489}, RuleIDs: []string{"native"},
						WhatItDoes: "Strip debug headers (X-Debug-*, X-Trace-*).",
						WhyDisable: "Rarely worth disabling."},
					{ID: "response-headers-remove-backend-server", Default: On, CWE: []int{200}, RuleIDs: []string{"native"},
						WhatItDoes: "Strip X-Backend-Server header.",
						WhyDisable: "Rarely worth disabling."},
					{ID: "response-headers-remove-version", Default: On, CWE: []int{200}, RuleIDs: []string{"native"},
						WhatItDoes: "Strip X-Version header.",
						WhyDisable: "Rarely worth disabling."},
				},
			},
		},
	}
}

func groupResponseInspection() Group {
	return Group{
		ID:          "response-inspection",
		Name:        "Response inspection",
		Description: "Native response-body inspection. Open-redirect detection and OpenAPI response-shape validation.",
		WhyDisable:  "Disable carefully when you don't inspect or modify response bodies (treats responses as opaque).",
		Leaves: []Leaf{
			{ID: "response-inspection-open-redirects", Default: On, CWE: []int{601}, RuleIDs: []string{"native"},
				WhatItDoes: "Detects Location headers pointing off-domain — fingerprint of open-redirect vulnerabilities.",
				WhyDisable: "Disable for routes that intentionally redirect off-domain — for example, auth providers."},
			{ID: "response-inspection-openapi-validation", Default: On, CWE: []int{20}, RuleIDs: []string{"native"},
				WhatItDoes: "Validates response shape against the route's OpenAPI spec.",
				WhyDisable: "Disable when responses don't always conform to the OpenAPI spec strictly."},
		},
	}
}
