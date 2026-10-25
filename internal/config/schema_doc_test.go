package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestSchemaDocDefaultsMatchCode keeps the Default column of every field
// table in docs/design/config-schema.md equal to what applyDefaults writes.
// The public reference pages are copied from those tables, so a default that
// drifts there spreads to the docs site unnoticed.
//
// A row is checked when its Default cell starts with a backticked value
// (`10MB`, `true`, `[]`); prose such as "inherit from global" or "from build"
// is skipped. A field inside an optional block the minimal config leaves out
// (cors, openapi, rate_limit) is skipped too, since its defaults only exist
// once the block is written.
func TestSchemaDocDefaultsMatchCode(t *testing.T) {
	doc, err := os.ReadFile("../../docs/design/config-schema.md")
	if err != nil {
		t.Fatal(err)
	}

	cfg := loadYAML(t, "version: v1beta1\nroutes:\n  - upstream: http://app:8000\n")
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		t.Fatal(err)
	}

	rows := documentedDefaults(string(doc))
	checked := 0
	for _, row := range rows {
		got, found, parentFound := lookupPath(tree, row.path)
		switch {
		case !parentFound:
			continue
		case !found:
			if !isZeroDefault(row.value) {
				t.Errorf("config-schema.md:%d: %s documents default %q, but the code sets no such field", row.line, row.path, row.value)
			}
		case render(got) != row.value:
			t.Errorf("config-schema.md:%d: %s documents default %q, the code applies %q", row.line, row.path, row.value, render(got))
		}
		checked++
	}
	// Guards the parser: if the table layout changes and nothing is read,
	// the test must not pass by checking nothing.
	if checked < 40 {
		t.Fatalf("checked only %d documented defaults; has the table layout in config-schema.md changed?", checked)
	}
}

type docDefault struct {
	line  int
	path  string
	value string
}

// documentedDefaults reads every markdown table that has a "Default" column
// and returns its rows whose first cell is a backticked field path and whose
// Default cell starts with a backticked value.
func documentedDefaults(doc string) []docDefault {
	lines := strings.Split(doc, "\n")
	var out []docDefault
	defaultCol := -1
	for i, l := range lines {
		if !strings.HasPrefix(l, "|") {
			defaultCol = -1
			continue
		}
		cells := splitRow(l)
		if i+1 < len(lines) && strings.HasPrefix(lines[i+1], "|---") {
			defaultCol = -1
			for j, c := range cells {
				if c == "Default" {
					defaultCol = j
				}
			}
			continue
		}
		if defaultCol < 0 || defaultCol >= len(cells) || strings.HasPrefix(l, "|---") {
			continue
		}
		path, ok := backticked(cells[0])
		if !ok || path != cells[0][1:len(cells[0])-1] {
			continue
		}
		value, ok := backticked(cells[defaultCol])
		if !ok {
			continue
		}
		if value == `""` {
			value = ""
		}
		out = append(out, docDefault{line: i + 1, path: path, value: value})
	}
	return out
}

func splitRow(l string) []string {
	parts := strings.Split(strings.Trim(l, "|"), "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// backticked returns the backticked value a cell starts with.
func backticked(cell string) (string, bool) {
	if !strings.HasPrefix(cell, "`") {
		return "", false
	}
	end := strings.Index(cell[1:], "`")
	if end < 0 {
		return "", false
	}
	return cell[1 : end+1], true
}

// lookupPath walks a dotted path such as global.accept.max_body_size or
// routes[].upstream_timeout (the first route) through the marshalled config.
// parentFound is false when a block above the field is absent.
func lookupPath(tree map[string]any, path string) (value any, found, parentFound bool) {
	var cur any = tree
	segs := strings.Split(path, ".")
	for i, seg := range segs {
		list := strings.HasSuffix(seg, "[]")
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false, false
		}
		v, ok := m[strings.TrimSuffix(seg, "[]")]
		if !ok {
			return nil, false, i == len(segs)-1
		}
		if list {
			items, ok := v.([]any)
			if !ok || len(items) == 0 {
				return nil, false, false
			}
			v = items[0]
		}
		cur = v
	}
	return cur, true, true
}

func isZeroDefault(v string) bool {
	switch v {
	case "", "0", "false", "[]", "{}":
		return true
	}
	return false
}

// render prints a marshalled value the way the schema doc writes defaults.
func render(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case int:
		return strconv.Itoa(x)
	case bool:
		return strconv.FormatBool(x)
	case []any:
		if len(x) == 0 {
			return "[]"
		}
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = render(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		if len(x) == 0 {
			return "{}"
		}
		parts := make([]string, 0, len(x))
		for k, e := range x {
			parts = append(parts, k+": "+render(e))
		}
		return strings.Join(parts, ", ")
	default:
		return fmt.Sprint(x)
	}
}
