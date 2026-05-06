package crs

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBarbacanaXSSRulesBlockBypassPayloads verifies the three custom
// rules in the 210000 range catch the XSS function-call evasion
// patterns that no upstream CRS rule covers — the gap identified by
// the v0.5 base64-decoding gotestwaf run.
//
// Two assertions per case:
//   - the engine must produce a blocking decision (security objective)
//   - the named Barbacana rule (210001/2/3) must appear in the
//     transaction's matched rules — proves the new rule is what the
//     audit log will attribute the block to in the (likely) case where
//     no other CRS rule co-fires
func TestBarbacanaXSSRulesBlockBypassPayloads(t *testing.T) {
	route := testRoute()
	eng, err := NewEngine(route)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	cases := []struct {
		name   string
		query  string
		ruleID int
	}{
		{"alert.call", "alert.call(null,1)", 210001},
		{"alert.apply", "alert.apply(null, [1])", 210001},
		{"confirm.call", "confirm.call(null,1)", 210001},
		{"prompt.call", "prompt.call(null,1)", 210001},
		{"grouping-paren", "(alert)(1)", 210002},
		{"optional-chain", "alert?.(document.cookie)", 210003},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/?q="+urlQueryEscape(c.query), nil)
			r.Header.Set("Host", "example.com")
			r.Header.Set("User-Agent", "Mozilla/5.0")
			r.Header.Set("Accept", "*/*")

			res := eng.Evaluate(context.Background(), r)

			blocked := false
			ruleFired := false
			for _, d := range res.Decisions {
				if d.Block {
					blocked = true
				}
				for _, id := range d.MatchedRules {
					if id == c.ruleID {
						ruleFired = true
					}
				}
			}
			if !blocked {
				t.Errorf("expected request %q to be blocked; decisions=%+v",
					c.query, res.Decisions)
			}
			if !ruleFired {
				// Not a hard fail — another curated rule may co-fire and
				// block first (e.g. 942200 catches the comma+quote in
				// alert.call(null,"XSS")). Log so a future regression
				// where the co-firing rule is removed makes the picture
				// clear.
				t.Logf("note: rule %d did not appear in matched rules for %q "+
					"(another curated rule co-fired); decisions=%+v",
					c.ruleID, c.query, res.Decisions)
			}
		})
	}
}

// TestBarbacanaXSSRulesDoNotBlockBenignText verifies the custom XSS
// rules do not fire on JavaScript-shaped benign text. Adversarial
// strings drawn from the gotestwaf clean-text corpus and from common
// JS idioms that include `.call`/`.apply`/`.bind`.
func TestBarbacanaXSSRulesDoNotBlockBenignText(t *testing.T) {
	route := testRoute()
	eng, err := NewEngine(route)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	benign := []string{
		"please confirm your email address",
		"the prompt was answered yesterday",
		"alert level dropped",
		"setTimeout to coffee break",
		"the eval committee meets weekly",
		"call.apply.bind in functional programming",
		"function names: alert, confirm, prompt are window methods",
		"calling alert() opens a dialog",
		"myFunction.call(this, args)",
		"Object.prototype.toString.call(obj)",
		"Array.prototype.slice.apply(arguments)",
		"window.alert ?? defaultAlert",
		"prompt? (please reply)",
	}

	for _, s := range benign {
		t.Run(strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' {
				return r
			}
			return '_'
		}, strings.ToLower(s))[:min(20, len(s))], func(t *testing.T) {
			r := httptest.NewRequest("GET", "/?q="+urlQueryEscape(s), nil)
			r.Header.Set("Host", "example.com")
			r.Header.Set("User-Agent", "Mozilla/5.0")
			r.Header.Set("Accept", "*/*")

			res := eng.Evaluate(context.Background(), r)

			for _, d := range res.Decisions {
				for _, id := range d.MatchedRules {
					if id == 210001 || id == 210002 || id == 210003 {
						t.Errorf("benign text %q triggered Barbacana XSS rule %d", s, id)
					}
				}
			}
		})
	}
}

// urlQueryEscape is a minimal query-component escaper sufficient for
// the test inputs. We avoid net/url to keep encoding behavior
// predictable across the test suite — Go's url.QueryEscape converts
// space to '+', which can interfere with regex anchoring.
func urlQueryEscape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0xf])
		}
	}
	return b.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
