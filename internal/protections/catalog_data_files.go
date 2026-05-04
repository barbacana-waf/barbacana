package protections

func groupLocalFileAccess() Group {
	return Group{
		ID:          "local-file-access",
		Name:        "Local file access",
		Description: "Local File Inclusion / path-traversal protection. Catches attempts to read files outside the intended scope.",
		WhyDisable:  "Disable carefully when your app doesn't read filesystem based on user input — for example, a fully containerized service with no filesystem access from request inputs. Rare.",
		Leaves: []Leaf{
			{ID: "local-file-access-dot-dot-paths", Default: On, CWE: []int{22, 23}, RuleIDs: []string{"930100", "930110"},
				WhatItDoes: "Detects classic path-traversal sequences (../, ..\\, /.../, encoded variants).",
				WhyDisable: "Disable if your app legitimately accepts ../-containing inputs — for example, a path-rewriting tool."},
			{ID: "local-file-access-os-files", Default: On, CWE: []int{22, 200}, RuleIDs: []string{"930120", "930121"},
				WhatItDoes: "Detects attempts to access OS system files (/etc/passwd, /proc/self/environ, C:\\Windows\\system32\\drivers\\etc\\hosts).",
				WhyDisable: "Moderate FP risk — fires on any app that legitimately displays file paths (file managers, IDE-in-browser, log viewers, build dashboards, dev tooling, security-research tools). The rule fires on inputs and responses; the response-side detection is where most FPs land. Disable if your app legitimately renders or references OS filesystem paths."},
			{ID: "local-file-access-dotfiles", Default: On, CWE: []int{22, 538}, RuleIDs: []string{"930130"},
				WhatItDoes: "Detects attempts to access restricted dotfiles (.htaccess, .git/, .svn/, .env).",
				WhyDisable: "Disable if your app legitimately serves these — for example, a Git-hosting platform serving .htaccess from repos."},
			{ID: "local-file-access-ai-tool-files", Default: On, CWE: []int{22, 538}, RuleIDs: []string{"930140"},
				WhatItDoes: "Detects AI-coding-assistant artifact paths (.continue/, .claude/, .aider*, .cursor/). New CRS v4 family targeting agent leakage.",
				WhyDisable: "Disable if your app legitimately exposes AI-tooling artifact paths."},
		},
	}
}

func groupRemoteFileFetch() Group {
	return Group{
		ID:          "remote-file-fetch",
		Name:        "Remote file fetch",
		Description: "Remote File Inclusion protection. Attacks that fetch attacker-controlled URLs and execute their content.",
		WhyDisable:  "Safe to disable when your app can't include remote files (no eval-from-URL pattern).",
		Leaves: []Leaf{
			{ID: "remote-file-fetch-ip-urls", Default: On, CWE: []int{98}, RuleIDs: []string{"931100"},
				WhatItDoes: "Detects URLs with literal IP addresses in parameter values — fingerprint of RFI probes.",
				WhyDisable: "Rarely worth disabling."},
			{ID: "remote-file-fetch-suspicious-param-names", Default: On, CWE: []int{98}, RuleIDs: []string{"931110"},
				WhatItDoes: "Detects URL payloads in parameters with known-vulnerable names (include=, template=, page=, path=).",
				WhyDisable: "Rarely worth disabling."},
			{ID: "remote-file-fetch-truncation-trick", Default: On, CWE: []int{98}, RuleIDs: []string{"931120"},
				WhatItDoes: "Detects URL payloads ending in ? — used to truncate filename-suffix appending in vulnerable PHP includes.",
				WhyDisable: "Rarely worth disabling."},
			{ID: "remote-file-fetch-external-urls", Default: Off, CWE: []int{98, 918}, RuleIDs: []string{"931130", "931131"},
				WhatItDoes: "Detects off-domain URL references in parameter values.",
				WhyEnable:  "Enable to add off-domain URL detection in inputs. Off by default because legitimate inputs frequently contain external URLs."},
		},
	}
}

func groupOutboundRequestForgery() Group {
	return Group{
		ID:          "outbound-request-forgery",
		Name:        "Outbound request forgery",
		Description: "Server-Side Request Forgery protection. Detects attempts to coerce the server into making outbound requests on the attacker's behalf.",
		WhyDisable:  "Safe to disable when your app can't make outbound requests (firewall-isolated, no DNS, no fetch APIs).",
		Leaves: []Leaf{
			{ID: "outbound-request-forgery-cloud-metadata", Default: On, CWE: []int{918}, RuleIDs: []string{"934110"},
				WhatItDoes: "Detects cloud-provider metadata URLs in parameter values (169.254.169.254, metadata.google.internal) — fingerprint of cloud-credential-theft attacks.",
				WhyDisable: "Rarely worth disabling."},
			{ID: "outbound-request-forgery-internal-addresses", Default: On, CWE: []int{918}, RuleIDs: []string{"934120", "934190"},
				WhatItDoes: "Detects scheme-less or IP-literal URLs in parameters that target internal addresses (localhost, 127.0.0.1, RFC1918 ranges).",
				WhyDisable: "Disable if your app legitimately accepts internal-hostname URLs as input."},
		},
	}
}

func groupFileUpload() Group {
	return Group{
		ID:          "file-upload",
		Name:        "File upload",
		Description: "Multipart-form-data attack detection (CRS) and validation (native).",
		WhyDisable:  "Safe to disable when your service has no file uploads or multipart handling.",
		Buckets: []L2{
			{
				ID:          "file-upload-attacks",
				Name:        "Attacks",
				Description: "CRS-backed multipart bypass / abuse detection.",
				Leaves: []Leaf{
					{ID: "file-upload-attacks-charset-trick", Default: On, CWE: []int{444}, RuleIDs: []string{"922100"},
						WhatItDoes: "Detects global _charset_ field definitions in multipart bodies — used to bypass content filters.",
						WhyDisable: "Rarely worth disabling."},
					{ID: "file-upload-attacks-content-type-trick", Default: On, CWE: []int{444}, RuleIDs: []string{"922110", "922140", "922150"},
						WhatItDoes: "Illegal CT charset parameters in multipart headers.",
						WhyDisable: "Rarely worth disabling."},
					{ID: "file-upload-attacks-deprecated-encoding", Default: On, CWE: []int{444}, RuleIDs: []string{"922120"},
						WhatItDoes: "Detects deprecated Content-Transfer-Encoding in multipart parts (RFC 7578 deprecated this in 2015).",
						WhyDisable: "Rarely worth disabling."},
					{ID: "file-upload-attacks-header-tricks", Default: On, CWE: []int{444}, RuleIDs: []string{"922130"},
						WhatItDoes: "Invalid characters in multipart-section headers — fingerprint of parser-bypass attempts.",
						WhyDisable: "Rarely worth disabling."},
				},
			},
			{
				ID:          "file-upload-limits",
				Name:        "Limits",
				Description: "Native multipart-upload validation rules and content-shape limits.",
				Leaves: []Leaf{
					{ID: "file-upload-limits-max-file-count", Default: On, CWE: []int{770}, RuleIDs: []string{"native"},
						WhatItDoes: "Per-route file-count cap enforced by the native multipart validator.",
						WhyDisable: "Disable when uploads can legitimately contain many files in a single request."},
					{ID: "file-upload-limits-max-file-size", Default: On, CWE: []int{400, 770, 434}, RuleIDs: []string{"native", "920400"},
						WhatItDoes: "Per-file size cap. Both native multipart validator and CRS rule 920400 contribute; one toggle controls both.",
						WhyDisable: "Disable for routes with large legitimate uploads."},
					{ID: "file-upload-limits-max-total-size", Default: On, CWE: []int{400, 770}, RuleIDs: []string{"920410"},
						WhatItDoes: "Per-request total upload-size cap — sum of all file parts in a single multipart request. Independent of per-file cap; a route may allow large individual files but cap total request size, or vice versa.",
						WhyDisable: "Disable for routes that legitimately accept large multi-file requests in aggregate (e.g., archive uploads)."},
					{ID: "file-upload-limits-allowed-types", Default: On, CWE: []int{434}, RuleIDs: []string{"native"},
						WhatItDoes: "MIME-type allow-list per route — rejects file parts whose declared CT isn't in the route's accept.upload_types.",
						WhyDisable: "Disable to allow any MIME type. Rare; usually a security mistake."},
					{ID: "file-upload-limits-double-extension", Default: On, CWE: []int{434}, RuleIDs: []string{"native"},
						WhatItDoes: "Detects file.php.jpg-style double-extension uploads — classic shell-upload trick on mod_rewrite-misconfigured Apache.",
						WhyDisable: "Disable if your app legitimately accepts files with composite extensions."},
					{ID: "file-upload-limits-executable", Default: On, CWE: []int{434}, RuleIDs: []string{"932180"},
						WhatItDoes: "Detects upload of executable file types (.exe, .dll, .so, .elf) — restricted file-upload check. Belongs with the other content-shape limits in this bucket.",
						WhyDisable: "Disable if your app legitimately accepts executable file uploads — for example, a malware-analysis service."},
				},
			},
		},
	}
}
