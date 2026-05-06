package protections

func groupBase64Decoding() Group {
	return Group{
		ID:          "base64-decoding",
		Name:        "Base64 decoding",
		Description: "Native base64-decoding stage. Surfaces base64-encoded payloads hidden in the URL path, query parameters, and request body, then feeds the decoded values to CRS as additional ARGS so attack rules evaluate them alongside the raw request. The original request is never modified — the upstream sees the bytes the client sent.",
		WhyDisable:  "Safe to disable when no clients legitimately send base64-encoded data and you've confirmed the latency overhead is unwelcome. Most apps benefit from it being on.",
		Leaves: []Leaf{
			{ID: "base64-decoding-path", Default: On, CWE: []int{20}, RuleIDs: []string{"native"},
				WhatItDoes: "Splits the normalized URL path on `/` and decodes each segment that looks like base64. Decoded values are emitted as synthetic PATH args so CRS rules see SQLi, XSS, etc. hidden inside path segments.",
				WhyDisable: "Disable for routes whose path segments legitimately contain base64-shaped tokens (e.g. opaque IDs the app issues itself) and where false-positive risk outweighs the coverage gain."},
			{ID: "base64-decoding-parameters", Default: On, CWE: []int{20}, RuleIDs: []string{"native"},
				WhatItDoes: "Decodes each query-parameter value that looks like base64. Decoded values are emitted as synthetic GET args under the original parameter name so CRS rules see attacks hidden inside parameters.",
				WhyDisable: "Disable for routes whose query parameters legitimately carry base64 (e.g. an `?image=` parameter on an inline-image API) where the decoded payload would predictably trip CRS."},
			{ID: "base64-decoding-body", Default: On, CWE: []int{20}, RuleIDs: []string{"native"},
				WhatItDoes: "Scans the buffered request body for runs of base64-alphabet characters and decodes each one. Decoded values are emitted as synthetic POST args. Content-type-agnostic: works for JSON, XML, form-encoded, and plain bodies.",
				WhyDisable: "Disable for endpoints where bodies legitimately embed base64 (file-upload metadata, signed payloads, multipart inline images) and the false-positive cost is real."},
			{ID: "base64-decoding-flood", Default: On, CWE: []int{400}, RuleIDs: []string{"native"},
				WhatItDoes: "Blocks requests that contain more than 50 successfully-decoded base64 values across the path, parameters, and body. Bounds the cost of the decoding stage and catches obvious decoder-flood DoS attempts.",
				WhyDisable: "Disable only on routes that legitimately receive many small base64-encoded values per request (rare) and where the per-request decoding work is acceptable."},
		},
	}
}
