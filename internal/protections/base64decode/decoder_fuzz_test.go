package base64decode

import (
	"encoding/base64"
	"testing"
	"unicode/utf8"
)

// FuzzTryDecode asserts that TryDecode upholds its documented contract for
// arbitrary input. The seed corpus mirrors the unit tests so the fuzzer
// starts from inputs that already exercise every code path.
func FuzzTryDecode(f *testing.F) {
	seeds := []string{
		"",
		"a",
		"ab",
		"abc",
		"abcd",
		"AAAA",
		"================",
		"abcd+/-_efgh",
		"not base64 at all, just words",
		base64.StdEncoding.EncodeToString([]byte("' OR 1=1--")),
		base64.RawURLEncoding.EncodeToString([]byte("' OR 1=1--")),
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)),
		base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa}),
		base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 'A', 'B'}),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, v string) {
		// Cap input length: TryDecode is called per token from request paths,
		// query values, and body fields, none of which exceed this in practice.
		// Skipping past the cap keeps fuzz runs from OOMing on adversarial
		// sizes without committing the entry to the corpus.
		if len(v) > 1<<16 {
			t.Skip()
		}

		out, ok := TryDecode(v)

		// Contract: when the decoder rejects, the output is the zero value.
		if !ok && out != "" {
			t.Fatalf("TryDecode(%q) = (%q, false); want (\"\", false)", v, out)
		}

		if ok {
			// Contract: a successful decode must be valid UTF-8. The caller
			// feeds this into CRS, which assumes well-formed text.
			if !utf8.ValidString(out) {
				t.Fatalf("TryDecode(%q) reported success but output is not valid UTF-8: %q", v, out)
			}
			// Contract: base64 decoding shrinks bytes (4 chars → 3 bytes), so
			// the decoded output is always shorter than the input. Catches
			// any future change that lets binary or transformed bytes leak
			// through with size > len(v).
			if len(out) > len(v) {
				t.Fatalf("TryDecode(%q) produced %d-byte output from %d-byte input", v, len(out), len(v))
			}
		}

		// Determinism: TryDecode is a pure function of its input. A second
		// call must produce the same result. This catches accidental use of
		// shared state (package vars, sync.Pool buffers reused across calls).
		out2, ok2 := TryDecode(v)
		if out != out2 || ok != ok2 {
			t.Fatalf("TryDecode(%q) not deterministic: first=(%q,%v) second=(%q,%v)", v, out, ok, out2, ok2)
		}
	})
}
