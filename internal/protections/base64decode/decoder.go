// Package base64decode implements a pipeline stage that surfaces
// base64-encoded payloads hidden inside the URL path, query parameters,
// and request body, feeding the decoded values to CRS for evaluation.
//
// The decoder is deliberately optimistic: it tries the four common
// base64 alphabets in turn and accepts the first decode that yields
// printable UTF-8. False positives on non-base64 strings are cheap (the
// decoders fail in microseconds); false negatives on real attack
// payloads are not. See the implementation plan for the discussion
// behind the chosen thresholds.
package base64decode

import (
	"encoding/base64"
	"unicode"
	"unicode/utf8"
)

// Tunables. These values are starting points — the implementation plan
// flags them as pending empirical measurement against gotestwaf and
// real traffic. Do not lift to user-config without that data.
const (
	// minLen is the shortest input we'll attempt to decode. Strings of
	// fewer than 4 characters cannot encode useful base64 content.
	minLen = 4
	// printableThreshold is the fraction of decoded bytes that must be
	// printable for the decode to be accepted. CRS won't fire on noise
	// anyway; this gate exists only to keep raw binary out of Coraza.
	printableThreshold = 0.7
)

// encodings is the priority-ordered list of decoders attempted per
// candidate string. RawURL/URL come first because URL-safe encodings
// are the common case for tokens that travel inside a URL (JWTs,
// OAuth state). RawStd/Std catch payloads embedded in JSON or form
// bodies.
var encodings = []*base64.Encoding{
	base64.RawURLEncoding,
	base64.URLEncoding,
	base64.RawStdEncoding,
	base64.StdEncoding,
}

// TryDecode attempts to decode v as base64 using each of the four
// encodings in priority order. It returns the decoded string and true
// on the first encoding that produces valid UTF-8 with at least
// printableThreshold printable runes; otherwise it returns "", false.
func TryDecode(v string) (string, bool) {
	if len(v) < minLen {
		return "", false
	}
	for _, enc := range encodings {
		out, err := enc.DecodeString(v)
		if err != nil {
			continue
		}
		if !utf8.Valid(out) {
			continue
		}
		if !printableEnough(out) {
			continue
		}
		return string(out), true
	}
	return "", false
}

// printableEnough reports whether a sufficient fraction of the runes
// in b are printable. Returns true for empty input — the caller
// already filtered short strings via minLen.
func printableEnough(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	total, printable := 0, 0
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		i += size
		total++
		if unicode.IsPrint(r) || r == '\n' || r == '\t' || r == '\r' {
			printable++
		}
	}
	return float64(printable)/float64(total) >= printableThreshold
}
