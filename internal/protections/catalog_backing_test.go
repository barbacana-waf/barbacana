package protections

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/barbacana-waf/barbacana"

// Labels that open the description of a leaf in knownGaps.
const (
	partiallyEnforced = "Partially enforced"
	notEnforcedYet    = "Not enforced yet"
)

// knownGaps lists the native leaves that do not fully work as their name
// promises, with the label their catalog description opens with. Each one is
// work still to do: implement it, remove the leaf (with a deprecation), or
// keep it here. TestNativeLeavesHaveCode keeps this list and the catalog text
// in step, and prints the list with go test -v.
var knownGaps = map[string]string{
	// Enforced by the server settings for every route; never raised by
	// name, so disabling the leaf has no effect.
	"http2-frame-flood":               partiallyEnforced,
	"http2-header-bomb":               partiallyEnforced,
	"http2-max-streams":               partiallyEnforced,
	"request-validation-slow-clients": partiallyEnforced,
	// Nothing implements these.
	"resource-limits-max-memory":             notEnforcedYet,
	"response-inspection-open-redirects":     notEnforcedYet,
	"response-inspection-openapi-validation": notEnforcedYet,
}

// TestNativeLeavesHaveCode fails when a native catalog leaf has no code that
// raises it: a leaf no code names is a protection operators can list,
// disable and rely on while it does nothing. It caught
// resource-limits-max-memory and resource-limits-max-inspection-size, which
// had been in the catalog for months with nothing behind them.
//
// A leaf counts as backed when non-test code outside the catalog data uses
// its ID, either as a string literal or through a constant that is itself
// referenced. A leaf in knownGaps is exempt, but its description must open
// with its label, no other leaf may use a label, and a "not enforced yet"
// leaf that code now raises must leave the list. CRS-backed leaves are
// checked by TestCRSLeavesHaveRules in the crs package.
func TestNativeLeavesHaveCode(t *testing.T) {
	refs := scanGoSource(t, "../..", "internal", "cmd")

	for _, id := range AllLeafIDs() {
		leaf, _, _, _ := LookupLeaf(id)
		label, known := knownGaps[id]
		labelled := strings.HasPrefix(leaf.WhatItDoes, partiallyEnforced+":") || strings.HasPrefix(leaf.WhatItDoes, notEnforcedYet+":")

		switch {
		case known && !strings.HasPrefix(leaf.WhatItDoes, label+":"):
			t.Errorf("leaf %s is a known gap; its WhatItDoes must open with %q", id, label+":")
		case !known && labelled:
			t.Errorf("leaf %s is labelled as a gap in the catalog but is not in knownGaps", id)
		}

		if !isNative(leaf) {
			continue
		}
		backed := refs.backs(id)
		switch {
		case !known && !backed:
			t.Errorf("native leaf %s: no code raises it. Implement it, or add it to knownGaps and open its WhatItDoes with %q or %q", id, partiallyEnforced+":", notEnforcedYet+":")
		case known && label == notEnforcedYet && backed:
			t.Errorf("native leaf %s is listed as %q but code now raises it; remove it from knownGaps and drop the label", id, notEnforcedYet)
		case known:
			t.Logf("WARNING known gap, %s: %s", strings.ToLower(label), id)
		}
	}
}

func isNative(l Leaf) bool {
	for _, r := range l.RuleIDs {
		if r == "native" {
			return true
		}
	}
	return false
}

// sourceRefs is what the scan learned about string identifiers in the code.
type sourceRefs struct {
	literals map[string]bool   // string literals used outside const declarations
	consts   map[string]string // "pkgdir.Name" -> value, for string constants
	used     map[string]bool   // "pkgdir.Name" identifiers referenced as values
}

// backs reports whether id is used as a literal or through a referenced
// constant.
func (s sourceRefs) backs(id string) bool {
	if s.literals[id] {
		return true
	}
	for key, v := range s.consts {
		if v == id && s.used[key] {
			return true
		}
	}
	return false
}

// scanGoSource parses the non-test Go files under root/dirs, leaving out the
// catalog data files whose job is to list every ID.
func scanGoSource(t *testing.T, root string, dirs ...string) sourceRefs {
	t.Helper()
	refs := sourceRefs{literals: map[string]bool{}, consts: map[string]string{}, used: map[string]bool{}}
	fset := token.NewFileSet()
	for _, d := range dirs {
		err := filepath.WalkDir(filepath.Join(root, d), func(path string, e fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.HasPrefix(name, "catalog_data_") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, filepath.Dir(path))
			scanFile(f, filepath.ToSlash(rel), refs)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return refs
}

func scanFile(f *ast.File, pkgDir string, refs sourceRefs) {
	// Import name -> package directory, for resolving pkg.Name selectors.
	imports := map[string]string{}
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if !strings.HasPrefix(p, modulePath+"/") {
			continue
		}
		dir := strings.TrimPrefix(p, modulePath+"/")
		name := dir[strings.LastIndex(dir, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		imports[name] = dir
	}

	// Identifiers that are not value references: declaration names, struct
	// field names in selectors and composite-literal keys.
	notRefs := map[*ast.Ident]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.GenDecl:
			if x.Tok != token.CONST {
				return true
			}
			for _, spec := range x.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					notRefs[name] = true
					if i < len(vs.Values) {
						if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							v, _ := strconv.Unquote(lit.Value)
							refs.consts[pkgDir+"."+name.Name] = v
							notRefs[name] = true
						}
					}
				}
			}
			// Literals inside const declarations are not uses.
			return false
		case *ast.SelectorExpr:
			notRefs[x.Sel] = true
			if pkg, ok := x.X.(*ast.Ident); ok {
				if dir, ok := imports[pkg.Name]; ok {
					refs.used[dir+"."+x.Sel.Name] = true
				}
			}
		case *ast.KeyValueExpr:
			if k, ok := x.Key.(*ast.Ident); ok {
				notRefs[k] = true
			}
		case *ast.FuncDecl:
			notRefs[x.Name] = true
		case *ast.TypeSpec:
			notRefs[x.Name] = true
		case *ast.Field:
			for _, n := range x.Names {
				notRefs[n] = true
			}
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				v, _ := strconv.Unquote(x.Value)
				refs.literals[v] = true
			}
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		if g, ok := n.(*ast.GenDecl); ok && g.Tok == token.CONST {
			return false
		}
		if id, ok := n.(*ast.Ident); ok && !notRefs[id] {
			refs.used[pkgDir+"."+id.Name] = true
		}
		return true
	})
}
