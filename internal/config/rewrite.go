package config

// RewritePath applies the rewrite rules to a request path.
// Used by the pipeline for OpenAPI validation against the rewritten path.
func RewritePath(rw *RewriteCfg, path string) string {
	if rw == nil {
		return path
	}
	if rw.Path != "" {
		return rw.Path
	}
	result := path
	if rw.StripPrefix != "" {
		if len(result) >= len(rw.StripPrefix) && result[:len(rw.StripPrefix)] == rw.StripPrefix {
			result = result[len(rw.StripPrefix):]
			if result == "" {
				result = "/"
			}
		}
	}
	if rw.AddPrefix != "" {
		result = rw.AddPrefix + result
	}
	return result
}
