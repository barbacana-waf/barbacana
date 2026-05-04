package protections

func groupPHP() Group {
	return Group{
		ID:          "php",
		Name:        "PHP",
		Description: "PHP-specific attack and leakage detection.",
		WhyDisable:  "Safe to disable when your app stack has no PHP anywhere.",
		Buckets: []L2{
			{
				ID:          "php-injection",
				Name:        "Injection",
				Description: "Server-side PHP code-injection patterns — open tags, function-name calls, stream wrappers, object deserialization, variable abuse.",
				Leaves: []Leaf{
					{ID: "php-injection-open-tags", Default: On, CWE: []int{94}, RuleIDs: []string{"933100", "933190"},
						WhatItDoes: "Detects literal <?php, <?=, or ?> markers in inputs — the basic shape of an attempt to inject inline PHP for server-side evaluation.",
						WhyDisable: "Disable if your app legitimately accepts PHP source as content — for example, a PHP-snippet paste service or a CMS storing raw PHP."},
					{ID: "php-injection-script-upload", Default: On, CWE: []int{434}, RuleIDs: []string{"933110", "933111", "933220"},
						WhatItDoes: "Catches uploads whose filename or body indicates a PHP script. Also catches PHP session-file uploads — the classic \"upload your shell\" attack against insecure upload endpoints.",
						WhyDisable: "Disable if your app legitimately accepts uploaded .php/.phtml files — for example, a code-hosting service."},
					{ID: "php-injection-config-directives", Default: On, CWE: []int{94}, RuleIDs: []string{"933120"},
						WhatItDoes: "Detects php.ini-style directive names (allow_url_include, auto_prepend_file, etc.) in request arguments.",
						WhyDisable: "Disable if your app legitimately accepts php.ini-style configuration as input. Very rare."},
					{ID: "php-injection-superglobal-names", Default: On, CWE: []int{94}, RuleIDs: []string{"933130", "933131", "933135"},
						WhatItDoes: "Catches $_GET, $_POST, $GLOBALS, etc. being passed as input — used in attacks that try to override or read PHP-internal variables.",
						WhyDisable: "Disable if input legitimately includes PHP superglobal names as values — for example, a security-research tool or PHP documentation site."},
					{ID: "php-injection-stream-wrappers", Default: On, CWE: []int{94, 98}, RuleIDs: []string{"933140", "933200"},
						WhatItDoes: "Detects PHP stream wrapper schemes (php://, phar://, expect://, data://) in inputs — used to bypass include/fopen filters and trigger code execution or arbitrary file reads. Includes phar:// deserialization patterns.",
						WhyDisable: "Disable if you legitimately reflect URI strings containing php://, data://, etc. into responses for documentation purposes."},
					{ID: "php-injection-dangerous-functions", Default: On, CWE: []int{94, 95}, RuleIDs: []string{"933150", "933160"},
						WhatItDoes: "Detects high-risk PHP function names (eval, assert, system, exec, passthru, shell_exec, popen, proc_open) in request arguments. Strong RCE signal.",
						WhyDisable: "Disable if your app legitimately exposes PHP function names as data. Very rare; likely a docs site for PHP."},
					{ID: "php-injection-suspicious-functions-aggressive", Default: Off, CWE: []int{94}, RuleIDs: []string{"933151", "933152", "933153", "933161"},
						WhatItDoes: "Medium-risk and low-value PHP function-name patterns (base64_decode, gzinflate, str_rot13, file-system helpers, low-value identifiers) in inputs. Aggressive variant of php-injection-dangerous-functions.",
						WhyEnable:  "Enable in conjunction with php-injection-dangerous-functions if your app has no PHP backend and you want broader coverage. FP rate higher because function names overlap common English words; low-value patterns folded into the same aggressive variant."},
					{ID: "php-injection-serialized-objects", Default: On, CWE: []int{502}, RuleIDs: []string{"933170"},
						WhatItDoes: "Detects PHP-serialized object literals (O:5:\"Class\":3:{...}) in request inputs — the trigger pattern for unserialize-based RCE chains (PHPGGC).",
						WhyDisable: "Disable if your app legitimately accepts serialized PHP objects as input — for example, a debugger interface."},
					{ID: "php-injection-indirect-function-calls", Default: On, CWE: []int{94}, RuleIDs: []string{"933180", "933210", "933211"},
						WhatItDoes: "Catches indirect-call syntax $foo($bar) and variable-named function references — used in obfuscated PHP RCE payloads to evade static-name detectors.",
						WhyDisable: "Disable only if your app deliberately exposes PHP variable-function call syntax as data."},
				},
			},
			{
				ID:          "php-data-leakage",
				Name:        "Data leakage",
				Description: "PHP info / source disclosure detection in responses.",
				WhyDisable:  "Disable if your app already masks PHP errors at the framework layer (custom error pages, sentry-style sink).",
				Leaves: []Leaf{
					{ID: "php-data-leakage-version-info", Default: On, CWE: []int{200}, RuleIDs: []string{"953100", "953101"},
						WhatItDoes: "Detects PHP information-disclosure markers in responses (PHP Version, Loaded Configuration File, Server API, etc.) — the classic phpinfo() output.",
						WhyDisable: "Disable if your app intentionally exposes a phpinfo()-style endpoint. Debug builds only — never in production."},
					{ID: "php-data-leakage-source-code", Default: On, CWE: []int{540}, RuleIDs: []string{"953110", "953120"},
						WhatItDoes: "Detects PHP source-code patterns in response bodies — fires when a misconfigured server returns .php files as text instead of executing them.",
						WhyDisable: "Disable if your app legitimately echoes PHP source — for example, a code-hosting service or paste tool."},
				},
			},
		},
	}
}

func groupJava() Group {
	return Group{
		ID:          "java",
		Name:        "Java",
		Description: "Java-specific attack and leakage detection.",
		WhyDisable:  "Safe to disable when your app stack has no Java anywhere.",
		Buckets: []L2{
			{
				ID:   "java-injection",
				Name: "Injection",
				Leaves: []Leaf{
					{ID: "java-injection-class-and-method-names", Default: On, CWE: []int{94}, RuleIDs: []string{"944100", "944130", "944250", "944260"},
						WhatItDoes: "Detects suspicious Java class names and method-invocation patterns in inputs (java.lang.Runtime, ProcessBuilder, URLClassLoader, getRuntime().exec()) — typical in OGNL/EL/Spring-style RCE payloads.",
						WhyDisable: "Disable if your app legitimately exposes Java class names or method-invocation patterns as data — for example, a JVM diagnostic tool."},
					{ID: "java-injection-struts2-runtime-exec", Default: On, CWE: []int{94, 78}, RuleIDs: []string{"944110"},
						WhatItDoes: "Specifically targets the Struts2 process-spawn pattern from CVE-2017-9805 (XML payload triggers Runtime.exec).",
						WhyDisable: "Disable when you've ruled out Struts2 entirely."},
					{ID: "java-injection-serialized-objects", Default: On, CWE: []int{502}, RuleIDs: []string{"944120", "944200", "944210", "944240"},
						WhatItDoes: "Detects Java serialized-object magic bytes (AC ED 00 05) and base64-encoded variants — the trigger for ysoserial-style deserialization gadget chains (CVE-2015-4852 family).",
						WhyDisable: "Disable if your app legitimately accepts serialized Java objects — for example, a debugging or replication endpoint."},
					{ID: "java-injection-script-upload", Default: On, CWE: []int{434}, RuleIDs: []string{"944140"},
						WhatItDoes: "Catches JSP/JSPX script uploads — the classic \"upload your webshell\" attack against Tomcat-based stacks.",
						WhyDisable: "Disable if your app legitimately accepts uploaded .jsp/.jspx files — for example, an enterprise CMS for JSP authoring."},
					{ID: "java-injection-log4shell", Default: On, CWE: []int{917}, RuleIDs: []string{"944150", "944151", "944152"},
						WhatItDoes: "Log4Shell detection — matches ${jndi:ldap://...} / ${jndi:rmi://...} and obfuscated variants (${${::-j}ndi:...}).",
						WhyDisable: "Disable when you've fully migrated off vulnerable Log4j versions and want to reduce overhead."},
					{ID: "java-injection-base64-encoded-keywords", Default: Off, CWE: []int{94}, RuleIDs: []string{"944300"},
						WhatItDoes: "Detects base64-encoded text whose decode hits a Java-suspicious keyword (java.lang., Runtime, ProcessBuilder).",
						WhyEnable:  "Enable for hardened environments where suspicious base64 strings in inputs warrant detection."},
				},
			},
			{
				ID:          "java-data-leakage",
				Name:        "Data leakage",
				Description: "Java response-side error/stack-trace leakage.",
				WhyDisable:  "Disable if your app already masks Java errors at the framework layer (custom error pages, Spring's ResponseEntityExceptionHandler).",
				Leaves: []Leaf{
					{ID: "java-data-leakage-stack-trace", Default: On, CWE: []int{209}, RuleIDs: []string{"952110"},
						WhatItDoes: "Detects Java stack-trace markers in responses (java.lang.NullPointerException, at com.example…) — fires when an unhandled exception leaks to clients.",
						WhyDisable: "Disable if your app already masks Java errors at the framework layer — for example, custom error pages or Spring's ResponseEntityExceptionHandler."},
				},
			},
		},
	}
}

func groupRuby() Group {
	return Group{
		ID:          "ruby",
		Name:        "Ruby",
		Description: "Ruby-specific attack and leakage detection.",
		WhyDisable:  "Safe to disable when your app stack has no Ruby anywhere.",
		Buckets: []L2{
			{
				ID:   "ruby-injection",
				Name: "Injection",
				Leaves: []Leaf{
					{ID: "ruby-injection-system-calls", Default: On, CWE: []int{94, 78}, RuleIDs: []string{"934150"},
						WhatItDoes: "Detects Ruby code-injection patterns in inputs — system(), eval(), IO.popen, ERB-style injection, backticks.",
						WhyDisable: "Disable if no Ruby runtime is involved at any layer."},
				},
			},
			{
				ID:          "ruby-data-leakage",
				Name:        "Data leakage",
				Description: "Ruby info / source disclosure detection in responses.",
				WhyDisable:  "Disable if your app already masks Ruby errors at the framework layer.",
				Leaves: []Leaf{
					{ID: "ruby-data-leakage-version-info", Default: On, CWE: []int{200}, RuleIDs: []string{"956100"},
						WhatItDoes: "Detects Ruby information-disclosure markers in responses (Ruby on Rails, RubyGems, version banners).",
						WhyDisable: "Disable if responses legitimately mention Ruby version banners."},
					{ID: "ruby-data-leakage-source-code", Default: Off, CWE: []int{540}, RuleIDs: []string{"956110"},
						WhatItDoes: "Detects Ruby source-code patterns in response bodies — def/end blocks, class X < Y, require '...'.",
						WhyEnable:  "Enable to detect raw Ruby source leakage when misconfigured servers serve .rb files as text. Off by default because patterns can match Ruby-discussion forum posts."},
				},
			},
		},
	}
}

func groupPerl() Group {
	return Group{
		ID:          "perl",
		Name:        "Perl",
		Description: "Perl-specific attack detection.",
		WhyDisable:  "Safe to disable when no Perl backend exists.",
		Leaves: []Leaf{
			{ID: "perl-injection-system-calls", Default: On, CWE: []int{94, 78}, RuleIDs: []string{"934140"},
				WhatItDoes: "Detects Perl injection patterns in inputs — system, exec, qx{}, backticks, open() with shell-mode.",
				WhyDisable: "Disable if no Perl backend exists."},
		},
	}
}

func groupIIS() Group {
	return Group{
		ID:          "iis",
		Name:        "IIS",
		Description: "Microsoft IIS-specific response-side disclosure detection. The family currently has only leakage rules; the L2 bucket is named iis-data-leakage for symmetry with other language families and to leave room for future injection-side rules.",
		WhyDisable:  "Safe to disable when you don't run IIS anywhere.",
		Buckets: []L2{
			{
				ID:   "iis-data-leakage",
				Name: "Data leakage",
				Leaves: []Leaf{
					{ID: "iis-data-leakage-install-paths", Default: On, CWE: []int{200, 540}, RuleIDs: []string{"954100", "954101"},
						WhatItDoes: "Detects IIS install paths in responses (C:\\inetpub\\wwwroot\\, C:\\Windows\\System32\\inetsrv\\).",
						WhyDisable: "Disable if responses legitimately reference IIS paths."},
					{ID: "iis-data-leakage-availability-errors", Default: On, CWE: []int{209}, RuleIDs: []string{"954110"},
						WhatItDoes: "Detects IIS application-availability error messages (HTTP Error 500.0 - Internal Server Error).",
						WhyDisable: "Disable for non-IIS stacks."},
					{ID: "iis-data-leakage-version-headers", Default: On, CWE: []int{200}, RuleIDs: []string{"954120", "954130"},
						WhatItDoes: "Detects IIS information disclosure (X-AspNet-Version-style version banners in responses).",
						WhyDisable: "Disable for non-IIS stacks."},
				},
			},
		},
	}
}

func groupJavaScript() Group {
	return Group{
		ID:          "javascript",
		Name:        "JavaScript",
		Description: "JavaScript-runtime attack detection — covers Node.js, Bun, Deno, browser JS, anywhere eval happens.",
		WhyDisable:  "Safe to disable when your app is sandboxed/serverless with no JS runtime, or front-end-only.",
		Leaves: []Leaf{
			{ID: "javascript-injection-eval", Default: On, CWE: []int{94, 95}, RuleIDs: []string{"934100", "934101"},
				WhatItDoes: "Detects JS code-injection patterns: eval(, new Function(, module.exports=, child_process, process.binding, require(...).",
				WhyDisable: "Disable if your app legitimately accepts JS source as input — for example, a JS sandbox or playground."},
			{ID: "javascript-infinite-loops", Default: On, CWE: []int{1333, 400}, RuleIDs: []string{"934160"},
				WhatItDoes: "Detects JS infinite-loop ReDoS patterns: while(!0), while(1), while(true) constructs that always evaluate true. Universal across JS engines.",
				WhyDisable: "Rarely worth disabling."},
			{ID: "javascript-prototype-pollution", Default: On, CWE: []int{1321}, RuleIDs: []string{"934130"},
				WhatItDoes: "Detects __proto__ and constructor.prototype in inputs — JS prototype-chain manipulation. Universal across Node, Bun, Deno, browser.",
				WhyDisable: "Disable if your app legitimately accepts __proto__-shaped JSON — for example, some legacy serialization formats."},
		},
	}
}
