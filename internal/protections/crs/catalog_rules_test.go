package crs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/barbacana-waf/barbacana/internal/protections"
)

// TestCRSLeavesHaveRules is TestNativeLeavesHaveCode for CRS-backed leaves:
// every rule ID a leaf lists must exist, either in the embedded CRS rule
// files or in Barbacana's own SecRules in this package. A rule ID that
// exists nowhere means the leaf, or part of it, does nothing.
// TestCatalogCRSMappingCrossReference checks the mapping between leaves and
// rule IDs, but not that the rules are there.
func TestCRSLeavesHaveRules(t *testing.T) {
	idPattern := regexp.MustCompile(`id:(\d{6})`)
	known := map[string]bool{}

	entries, err := FS.ReadDir("rules")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		b, err := FS.ReadFile("rules/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range idPattern.FindAllSubmatch(b, -1) {
			known[string(m[1])] = true
		}
	}
	crsRules := len(known)
	if crsRules < 100 {
		t.Fatalf("found only %d rule IDs in the embedded CRS files; are the rules fetched?", crsRules)
	}

	// Barbacana's own rules are SecLang held in string literals here.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				v, _ := strconv.Unquote(lit.Value)
				for _, m := range idPattern.FindAllStringSubmatch(v, -1) {
					known[m[1]] = true
				}
			}
			return true
		})
	}
	if len(known) == crsRules {
		t.Fatal("found no Barbacana-owned rule IDs in this package; has the way custom rules are defined changed?")
	}

	for _, id := range protections.AllLeafIDs() {
		leaf, _, _, _ := protections.LookupLeaf(id)
		for _, r := range leaf.RuleIDs {
			if r != "native" && !known[r] {
				t.Errorf("leaf %s lists rule %s, which exists neither in the embedded CRS rules nor in Barbacana's own rules", id, r)
			}
		}
	}
}
