package response

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestShouldMask_GoStackTrace(t *testing.T) {
	body := []byte(`panic: runtime error: invalid memory address
goroutine 1 [running]:
main.main()
	/app/main.go:42 +0x10
`)
	if !ShouldMask(body) {
		t.Error("expected Go stack trace to be masked")
	}
}

func TestShouldMask_PythonTraceback(t *testing.T) {
	body := []byte(`Traceback (most recent call last):
  File "/app/main.py", line 42, in <module>
    raise ValueError("bad")
ValueError: bad
`)
	if !ShouldMask(body) {
		t.Error("expected Python traceback to be masked")
	}
}

func TestShouldMask_JavaException(t *testing.T) {
	body := []byte(`Exception in thread "main" java.lang.NullPointerException
	at MyClass.main(MyClass.java:42)
`)
	if !ShouldMask(body) {
		t.Error("expected Java exception to be masked")
	}
}

func TestShouldMask_PHPFatalError(t *testing.T) {
	body := []byte(`<b>Fatal error:</b> Uncaught Error: Call to undefined function
Stack trace:
#0 /app/index.php(5)
`)
	if !ShouldMask(body) {
		t.Error("expected PHP fatal error to be masked")
	}
}

func TestShouldMask_HTMLErrorPage(t *testing.T) {
	body := []byte(`<!DOCTYPE html><html><head><title>500 Internal Server Error</title></head>`)
	if !ShouldMask(body) {
		t.Error("expected HTML 500 page to be masked")
	}
}

func TestShouldMask_NodeStackTrace(t *testing.T) {
	body := []byte(`TypeError: foo
    at Object.<anonymous> (/app/server.js:42:12)`)
	if !ShouldMask(body) {
		t.Error("expected Node stack trace to be masked")
	}
}

func TestShouldMask_MySQLError(t *testing.T) {
	body := []byte(`MySQL server returned an error: ER_DUP_ENTRY`)
	if !ShouldMask(body) {
		t.Error("expected MySQL error to be masked")
	}
}

func TestShouldMask_SQLState(t *testing.T) {
	body := []byte(`SQLSTATE[42000]: Syntax error or access violation`)
	if !ShouldMask(body) {
		t.Error("expected SQLSTATE to be masked")
	}
}

func TestShouldMask_OracleError(t *testing.T) {
	body := []byte(`ORA-00942: table or view does not exist`)
	if !ShouldMask(body) {
		t.Error("expected Oracle error to be masked")
	}
}

func TestShouldMask_CleanJSONError(t *testing.T) {
	body := []byte(`{"error":"internal server error","code":500}`)
	if ShouldMask(body) {
		t.Error("clean JSON error should NOT be masked")
	}
}

func TestShouldMask_PlainText404(t *testing.T) {
	body := []byte(`Not found.`)
	if ShouldMask(body) {
		t.Error("plain not-found body should NOT be masked")
	}
}

func TestShouldMask_OnlyFirst8KB(t *testing.T) {
	// Pad with whitespace so the panic marker sits beyond the inspection window.
	pad := strings.Repeat("a", MaxInspectBytes+1)
	body := []byte(pad + "panic: bad")
	if ShouldMask(body) {
		t.Error("pattern past 8KB window should NOT trigger masking")
	}
}

func TestIsTextContentType(t *testing.T) {
	cases := []struct {
		ct   string
		want bool
	}{
		{"", true},
		{"text/html", true},
		{"text/html; charset=utf-8", true},
		{"text/plain", true},
		{"application/json", true},
		{"application/xml", true},
		{"application/javascript", true},
		{"application/problem+json", true},
		{"application/octet-stream", false},
		{"image/png", false},
		{"image/jpeg", false},
		{"video/mp4", false},
		{"font/woff2", false},
	}
	for _, c := range cases {
		if got := IsTextContentType(c.ct); got != c.want {
			t.Errorf("IsTextContentType(%q) = %v, want %v", c.ct, got, c.want)
		}
	}
}

func TestIsErrorStatus(t *testing.T) {
	cases := []struct {
		code int
		want bool
	}{
		{200, false},
		{301, false},
		{399, false},
		{400, true},
		{404, true},
		{500, true},
		{599, true},
		{600, false},
	}
	for _, c := range cases {
		if got := IsErrorStatus(c.code); got != c.want {
			t.Errorf("IsErrorStatus(%d) = %v, want %v", c.code, got, c.want)
		}
	}
}

func TestMaskedBody_ContainsRequestID(t *testing.T) {
	body := MaskedBody("req-12345")
	if !strings.Contains(string(body), `"request_id":"req-12345"`) {
		t.Errorf("masked body missing request_id: %s", body)
	}
	if !strings.Contains(string(body), `"error":"An unexpected error occurred"`) {
		t.Errorf("masked body missing generic error: %s", body)
	}
}

func TestMaskedBody_EscapesQuotes(t *testing.T) {
	body := MaskedBody(`evil"id`)
	s := string(body)
	// The dangerous quote inside the request ID must appear escaped.
	if !strings.Contains(s, `\"`) {
		t.Errorf("quote not escaped: %s", s)
	}
	// And it must round-trip through encoding/json without error.
	var parsed map[string]string
	if err := json.Unmarshal([]byte(s), &parsed); err != nil {
		t.Fatalf("masked body is not valid JSON: %v (%s)", err, s)
	}
	if parsed["request_id"] != `evil"id` {
		t.Errorf("round-tripped request_id = %q, want %q", parsed["request_id"], `evil"id`)
	}
}

func TestDisabled(t *testing.T) {
	if Disabled(map[string]bool{}) {
		t.Error("should not be disabled by default")
	}
	if !Disabled(map[string]bool{ResponseErrorMasking: true}) {
		t.Error("should be disabled when name is in disabled set")
	}
}
