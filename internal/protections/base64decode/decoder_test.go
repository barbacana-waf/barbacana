package base64decode

import (
	"encoding/base64"
	"testing"
)

func TestTryDecodeStdPaddedSQLi(t *testing.T) {
	const sqli = "' OR 1=1--"
	in := base64.StdEncoding.EncodeToString([]byte(sqli))
	out, ok := TryDecode(in)
	if !ok {
		t.Fatalf("TryDecode(%q) failed; want %q", in, sqli)
	}
	if out != sqli {
		t.Errorf("TryDecode(%q) = %q; want %q", in, out, sqli)
	}
}

func TestTryDecodeRawURLUnpaddedSQLi(t *testing.T) {
	const sqli = "' OR 1=1--"
	in := base64.RawURLEncoding.EncodeToString([]byte(sqli))
	out, ok := TryDecode(in)
	if !ok {
		t.Fatalf("TryDecode(%q) failed; want %q", in, sqli)
	}
	if out != sqli {
		t.Errorf("TryDecode(%q) = %q; want %q", in, out, sqli)
	}
}

func TestTryDecodeJWTHeaderEmits(t *testing.T) {
	// JWT-style URL-safe unpadded; harmless JSON. The decoder MUST emit
	// it (printable JSON), but the CRS wiring test in crs/ verifies that
	// no rule fires on the decoded value.
	jwtHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	if _, ok := TryDecode(jwtHeader); !ok {
		t.Errorf("TryDecode(%q) failed; expected JWT header to be emitted", jwtHeader)
	}
}

func TestTryDecodeShortSkipped(t *testing.T) {
	// "abc" decodes via base64, but is 3 chars → below minLen.
	if out, ok := TryDecode("abc"); ok {
		t.Errorf("TryDecode(%q) = (%q, true); want skip", "abc", out)
	}
}

func TestTryDecodeMixedAlphabetSkipped(t *testing.T) {
	// Contains both '+' (std) and '-' (URL-safe). No single decoder
	// will accept it.
	in := "abcd+/-_efgh"
	if out, ok := TryDecode(in); ok {
		t.Errorf("TryDecode(%q) = (%q, true); want skip", in, out)
	}
}

func TestTryDecodeBinaryFailsUTF8(t *testing.T) {
	// Encode a byte sequence that decodes to non-UTF-8 bytes.
	binary := []byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa}
	in := base64.StdEncoding.EncodeToString(binary)
	if out, ok := TryDecode(in); ok {
		t.Errorf("TryDecode(%q) = (%q, true); want skip (non-UTF-8)", in, out)
	}
}

func TestTryDecodeMostlyControlCharsSkipped(t *testing.T) {
	// Mostly non-printable control bytes; valid UTF-8 but should fail
	// the printable-ratio gate.
	noisy := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 'A', 'B'}
	in := base64.StdEncoding.EncodeToString(noisy)
	if out, ok := TryDecode(in); ok {
		t.Errorf("TryDecode(%q) = (%q, true); want skip (low printable ratio)", in, out)
	}
}
