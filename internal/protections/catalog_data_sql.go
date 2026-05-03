package protections

func groupSQL() Group {
	return Group{
		ID:          "sql",
		Name:        "SQL",
		Description: "SQL-related protection: injection detection across all dialects plus per-vendor error-leakage detection.",
		WhyDisable:  "Safe to disable when your app has no SQL backend at all (e.g., NoSQL-only API, no DB).",
		Buckets: []L2{
			{
				ID:          "sql-injection",
				Name:        "Injection",
				Description: "Server-side SQL injection detection.",
				WhyDisable:  "Disable when you have a hosted DB-as-a-service that enforces queries server-side (Supabase, Hasura) and want to keep error masking active at L2 sql-data-leakage.",
				Leaves: []Leaf{
					{
						ID: "sql-injection-generic", Default: On, CWE: []int{89}, RuleIDs: []string{"942100", "942101"},
						WhatItDoes: "Generic SQLi detection via the libinjection tokenizer — recognizes SQL fingerprints across many dialects without per-dialect regex.",
						WhyDisable: "Disable only if generic detection produces FPs that more specific leaves don't cover. Rare.",
					},
					{
						ID: "sql-injection-generic-aggressive", Default: Off, CWE: []int{89},
						RuleIDs:    []string{"942330", "942370", "942380", "942390", "942400", "942470", "942480", "942490"},
						WhatItDoes: "Broad-stroke SQLi probe patterns supplementing the tokenizer. Aggressive variant of sql-injection-generic; same detection family, higher FP cost.",
						WhyEnable:  "Enable for paranoid SQLi coverage on hardened environments where the tokenizer's coverage isn't enough. FP rates are non-trivial on free-text inputs — pair with route-level accepts: [text] to scope it.",
					},
					{
						ID: "sql-injection-operators", Default: On, CWE: []int{89}, RuleIDs: []string{"942120", "942250", "942251"},
						WhatItDoes: "Detects SQL operator keywords in suspicious positions — MATCH AGAINST, HAVING, LIKE followed by single-char tokens.",
						WhyDisable: "Disable if SQL operator names (AND, OR, LIKE, MATCH, HAVING) appear legitimately in free-text inputs — for example, search queries against a literature corpus.",
					},
					{
						ID: "sql-injection-function-calls", Default: On, CWE: []int{89}, RuleIDs: []string{"942150", "942151", "942152", "942410"},
						WhatItDoes: "Detects SQL function names in suspicious positions (CHAR(), CONVERT(), SUBSTRING(), vendor-specific helpers) used to avoid quote literals.",
						WhyDisable: "Disable if SQL function names appear legitimately in inputs — for example, a SQL-reference docs site.",
					},
					{
						ID: "sql-injection-system-schema-names", Default: On, CWE: []int{89}, RuleIDs: []string{"942140"},
						WhatItDoes: "Detects reserved schema/database names in inputs (information_schema, pg_catalog, mysql.user) — fingerprint of reconnaissance probes.",
						WhyDisable: "Disable if your app legitimately echoes DB/schema names — for example, a DBA dashboard or SQL documentation site.",
					},
					{
						ID: "sql-injection-sql-comments", Default: On, CWE: []int{89}, RuleIDs: []string{"942440", "942500"},
						WhatItDoes: "MySQL inline-comment markers and comment-sequence detection — used to bypass keyword filters by commenting out tokens mid-query.",
						WhyDisable: "Disable if input legitimately contains /* */ or # comment markers — for example, a SQL editor or comment-rich free text.",
					},
					{
						ID: "sql-injection-comments-in-json", Default: Off, CWE: []int{89}, RuleIDs: []string{"942200"},
						WhatItDoes: "Aggressive variant — fires on , \"key\":\"... patterns common in multi-key JSON bodies. Detects real MySQL comment/space-obfuscation but blocks ordinary JSON when active.",
						WhyEnable:  "Enable only on routes that don't accept JSON bodies with multiple keys, or in detect-only mode. FP-prone on ordinary multi-key JSON.",
					},
					{
						ID: "sql-injection-backticks", Default: On, CWE: []int{89}, RuleIDs: []string{"942510", "942511"},
						WhatItDoes: "Backtick bypass — `id`-style identifier quoting used to evade simple regex filters.",
						WhyDisable: "Disable if input legitimately contains backticks — for example, a Markdown editor or code-snippet tool.",
					},
					{
						ID: "sql-injection-hex-encoded", Default: On, CWE: []int{89}, RuleIDs: []string{"942450"},
						WhatItDoes: "Hex-encoded SQLi payloads (0x5365…) — used to bypass quote/keyword filters by passing the payload as binary.",
						WhyDisable: "Disable if input legitimately contains long hex strings — for example, a binary-blob upload echoed back.",
					},
					{
						ID: "sql-injection-string-concatenation", Default: On, CWE: []int{89}, RuleIDs: []string{"942360", "942362"},
						WhatItDoes: "Concatenated SQLi (CONCAT(), ||-style concatenation operators).",
						WhyDisable: "Disable if input legitimately contains SQL concat syntax — for example, a SQL playground.",
					},
					{
						ID: "sql-injection-special-character-density", Default: Off, CWE: []int{89}, RuleIDs: []string{"942420", "942421", "942430", "942431", "942432", "942460"},
						WhatItDoes: "Meta-character anomaly detection — flags args/cookies with abnormal density of SQL meta-characters. Strict thresholds at higher paranoia tiers.",
						WhyEnable:  "Enable for paranoid coverage on locked-down routes where high density of SQL meta-characters in inputs is anomalous.",
					},
					{
						ID: "sql-injection-time-based", Default: On, CWE: []int{89}, RuleIDs: []string{"942160", "942170", "942280"},
						WhatItDoes: "Time-based blind SQLi: sleep(), benchmark(), pg_sleep(), WAITFOR DELAY. The attacker can't see results so they exfiltrate via response timing.",
						WhyDisable: "Disable if upstream legitimately runs slow queries that mention timing functions — for example, a query-builder tool.",
					},
					{
						ID: "sql-injection-always-true", Default: Off, CWE: []int{89}, RuleIDs: []string{"942130", "942131"},
						WhatItDoes: "Boolean-based SQLi tautology detection (' OR '1'='1, 1=1, ' OR true).",
						WhyEnable:  "Enable when broader tautology coverage matters and your inputs don't contain English or/and near digits or quotes. FP-prone on natural-language inputs.",
					},
					{
						ID: "sql-injection-union-select", Default: On, CWE: []int{89}, RuleIDs: []string{"942270", "942361"},
						WhatItDoes: "Detects UNION SELECT and ALTER TABLE probe patterns.",
						WhyDisable: "Disable if input legitimately contains UNION/SELECT keywords — for example, a SQL-tutorial site.",
					},
					{
						ID: "sql-injection-if-statements", Default: On, CWE: []int{89}, RuleIDs: []string{"942230", "942300"},
						WhatItDoes: "Conditional SQLi probes — IF(1=1, ...), CASE WHEN ..., comment-conditional injection.",
						WhyDisable: "Disable if input legitimately contains conditional SQL syntax — for example, a SQL editor preview.",
					},
					{
						ID: "sql-injection-multiple-statements", Default: Off, CWE: []int{89}, RuleIDs: []string{"942210", "942310"},
						WhatItDoes: "Chained SQLi — multiple statements separated by ;, used to append a DROP TABLE to a query.",
						WhyEnable:  "Enable for hardened environments where multi-statement payloads (;-separated statements) warrant detection.",
					},
					{
						ID: "sql-injection-query-closers", Default: On, CWE: []int{89}, RuleIDs: []string{"942530"},
						WhatItDoes: "Query-termination markers ('-- , ';--, ';#) — the classic SQLi closer that comments out the rest of the original query.",
						WhyDisable: "Disable if your app stores raw SQL queries — for example, a SQL playground or admin console.",
					},
					{
						ID: "sql-injection-overflow-probes", Default: On, CWE: []int{89}, RuleIDs: []string{"942220"},
						WhatItDoes: "Detects integer-overflow probe values from skipfish-style fuzzers (2.2250738585072011e-308 and similar).",
						WhyDisable: "Rarely worth disabling.",
					},
					{
						ID: "sql-injection-login-bypass", Default: On, CWE: []int{89, 287}, RuleIDs: []string{"942180", "942260", "942520", "942522", "942540"},
						WhatItDoes: "Detects login-bypass SQLi patterns — ' UNION SELECT, split-query attacks, concat-bypass.",
						WhyDisable: "Disable if your auth flow legitimately accepts SQL-shaped strings. Extremely rare.",
					},
					{
						ID: "sql-injection-quotes-in-text", Default: Off, CWE: []int{89, 287}, RuleIDs: []string{"942521"},
						WhatItDoes: "Aggressive variant — catches FP-prone auth-bypass shapes that fire on JSON values containing apostrophes. Detects real attacks but at significant FP cost.",
						WhyEnable:  "Enable only on closed-corpus apps where input is API-shaped (no apostrophe-containing free text). FP-prone on names like \"O'Brien\" and product names like \"d'or 1st\".",
					},
					{
						ID: "sql-injection-mssql-specific", Default: On, CWE: []int{89}, RuleIDs: []string{"942190", "942240"},
						WhatItDoes: "MSSQL-specific code execution patterns (xp_cmdshell, OPENROWSET, charset-switch DoS).",
						WhyDisable: "Disable if no MSSQL backend exists.",
					},
					{
						ID: "sql-injection-stored-procedures", Default: On, CWE: []int{89}, RuleIDs: []string{"942320", "942321", "942350"},
						WhatItDoes: "Detects stored-procedure invocation patterns and MySQL UDF injection (CREATE FUNCTION lib_mysqludf_sys_exec).",
						WhyDisable: "Disable if you don't use MySQL/PostgreSQL stored procedures (or any at all).",
					},
					{
						ID: "sql-injection-mongodb-operators", Default: On, CWE: []int{943}, RuleIDs: []string{"942290"},
						WhatItDoes: "MongoDB-style NoSQLi — {$ne: null}, {$gt: \"\"}, JSON-shaped operator injection.",
						WhyDisable: "Disable if no MongoDB backend exists or your driver uses parameterized queries.",
					},
					{
						ID: "sql-injection-json-operators", Default: On, CWE: []int{89}, RuleIDs: []string{"942550"},
						WhatItDoes: "JSON-based SQLi — payloads exploiting JSON-aware query syntax in MySQL 5.7+ / PostgreSQL JSON operators.",
						WhyDisable: "Disable if your DB driver uses parameterized JSON arguments.",
					},
					{
						ID: "sql-injection-scientific-notation", Default: On, CWE: []int{89}, RuleIDs: []string{"942560"},
						WhatItDoes: "Scientific-notation SQLi payloads exploiting MySQL's lax numeric parsing (1e0 parses to 1) to slip through filters that match decimal digits.",
						WhyDisable: "Rarely worth disabling.",
					},
				},
			},
			{
				ID:          "sql-data-leakage",
				Name:        "Data leakage",
				Description: "Per-vendor SQL error leakage detection in responses. Each leaf catches that vendor's distinctive error format.",
				WhyDisable:  "Disable if your app already masks DB errors at the framework layer (no DB error ever reaches the response body).",
				Leaves: []Leaf{
					{ID: "sql-data-leakage-mssql", Default: On, CWE: []int{209}, RuleIDs: []string{"951220"}, WhatItDoes: "MSSQL error patterns (Unclosed quotation mark, Microsoft OLE DB Provider, [SQL Server]).", WhyDisable: "Disable if no MSSQL backend exists."},
					{ID: "sql-data-leakage-msaccess", Default: On, CWE: []int{209}, RuleIDs: []string{"951110"}, WhatItDoes: "Microsoft Access error patterns (Microsoft JET Database Engine, Syntax error in query expression).", WhyDisable: "Disable if no MS Access backend exists."},
					{ID: "sql-data-leakage-oracle", Default: On, CWE: []int{209}, RuleIDs: []string{"951120"}, WhatItDoes: "Oracle error patterns (ORA-, PL/SQL, Oracle Database).", WhyDisable: "Disable if no Oracle backend exists."},
					{ID: "sql-data-leakage-db2", Default: On, CWE: []int{209}, RuleIDs: []string{"951130"}, WhatItDoes: "IBM DB2 error patterns (DB2 SQL error, SQLCODE=).", WhyDisable: "Disable if no DB2 backend exists."},
					{ID: "sql-data-leakage-informix", Default: On, CWE: []int{209}, RuleIDs: []string{"951180"}, WhatItDoes: "Informix error patterns.", WhyDisable: "Disable if no Informix backend exists."},
					{ID: "sql-data-leakage-sybase", Default: On, CWE: []int{209}, RuleIDs: []string{"951260"}, WhatItDoes: "Sybase error patterns.", WhyDisable: "Disable if no Sybase backend exists."},
					{ID: "sql-data-leakage-mysql", Default: On, CWE: []int{209}, RuleIDs: []string{"951230"}, WhatItDoes: "MySQL error patterns (You have an error in your SQL syntax, mysql_fetch_array()).", WhyDisable: "Disable if no MySQL backend exists."},
					{ID: "sql-data-leakage-postgres", Default: On, CWE: []int{209}, RuleIDs: []string{"951240"}, WhatItDoes: "PostgreSQL error patterns (ERROR: invalid input syntax, pg_query()).", WhyDisable: "Disable if no PostgreSQL backend exists."},
					{ID: "sql-data-leakage-sqlite", Default: On, CWE: []int{209}, RuleIDs: []string{"951250"}, WhatItDoes: "SQLite error patterns (SQLite/JDBCDriver, near \"...\": syntax error).", WhyDisable: "Disable if no SQLite backend exists."},
					{ID: "sql-data-leakage-firebird", Default: On, CWE: []int{209}, RuleIDs: []string{"951150"}, WhatItDoes: "Firebird error patterns.", WhyDisable: "Disable if no Firebird backend exists."},
					{ID: "sql-data-leakage-frontbase", Default: On, CWE: []int{209}, RuleIDs: []string{"951160"}, WhatItDoes: "Frontbase error patterns.", WhyDisable: "Disable if no Frontbase backend exists."},
					{ID: "sql-data-leakage-hsqldb", Default: On, CWE: []int{209}, RuleIDs: []string{"951170"}, WhatItDoes: "HSQLDB error patterns.", WhyDisable: "Disable if no HSQLDB backend exists."},
					{ID: "sql-data-leakage-ingres", Default: On, CWE: []int{209}, RuleIDs: []string{"951190"}, WhatItDoes: "Ingres error patterns.", WhyDisable: "Disable if no Ingres backend exists."},
					{ID: "sql-data-leakage-interbase", Default: On, CWE: []int{209}, RuleIDs: []string{"951200"}, WhatItDoes: "Interbase error patterns.", WhyDisable: "Disable if no Interbase backend exists."},
					{ID: "sql-data-leakage-maxdb", Default: On, CWE: []int{209}, RuleIDs: []string{"951210"}, WhatItDoes: "MaxDB error patterns.", WhyDisable: "Disable if no MaxDB backend exists."},
					{ID: "sql-data-leakage-emc", Default: On, CWE: []int{209}, RuleIDs: []string{"951140"}, WhatItDoes: "EMC SQL error patterns.", WhyDisable: "Disable if no EMC DB backend exists."},
				},
			},
		},
	}
}
