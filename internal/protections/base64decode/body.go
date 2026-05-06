package base64decode

import (
	"strconv"

	"github.com/barbacana-waf/barbacana/internal/protections"
)

// scanBody walks the buffered body as a flat byte stream, finding
// runs of base64-alphabet characters of at least minLen and emitting
// a synthetic POST arg for each run that decodes successfully.
//
// The flat scan is deliberately content-type-agnostic: a base64 blob
// inside JSON, XML, form-encoded, or plain text all surface the same
// way. Re-parsing the body per content type would duplicate stages
// 3-4 without earning new coverage for v0.5.
func scanBody(body []byte, ia *protections.InspectionArgs, budget *budget) {
	if len(body) == 0 || budget.exceeded() {
		return
	}
	idx := 0
	i := 0
	for i < len(body) {
		if !isBase64Byte(body[i]) {
			i++
			continue
		}
		j := i + 1
		for j < len(body) && isBase64Byte(body[j]) {
			j++
		}
		// Allow up to two trailing '=' padding characters.
		for k := 0; k < 2 && j < len(body) && body[j] == '='; k++ {
			j++
		}
		if j-i >= minLen {
			run := string(body[i:j])
			if decoded, ok := TryDecode(run); ok {
				if !budget.consume() {
					return
				}
				ia.POST = append(ia.POST, protections.ArgPair{
					Name:  "body.b64decoded." + strconv.Itoa(idx),
					Value: decoded,
				})
				idx++
			}
		}
		i = j
	}
}

// isBase64Byte reports whether b is a member of either of the standard
// base64 alphabets (excluding the '=' padding character — the scanner
// handles padding separately so a trailing '=' doesn't extend the run
// past a non-base64 boundary).
func isBase64Byte(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z':
		return true
	case b >= 'a' && b <= 'z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '+' || b == '/' || b == '-' || b == '_':
		return true
	}
	return false
}
