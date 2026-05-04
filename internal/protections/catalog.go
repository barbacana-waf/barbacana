// Package protections defines the Protection interface and the canonical-name
// catalog used for config validation, disable-list resolution, audit-log CWE
// enrichment, and HTTP block-status resolution.
//
// The catalog is the single source of truth for the WAF's protection surface.
// Every protection appears as a Leaf inside an L2 bucket (or directly under
// an L1 family for flat families), carrying its canonical ID, default state,
// CWE list, contributing CRS rule IDs (or "native"), and developer-facing
// prose (WhatItDoes, WhyDisable, WhyEnable). All accessors derive from the
// Catalog variable; tests pin the structure via TestCatalogIntegrity.
//
// # Three-level taxonomy
//
// The catalog is a tree: L1 family → L2 bucket → leaf. The L1 is a coarse
// surface (e.g. "sql-injection"); the L2 is a situational bucket inside it
// corresponding to a real developer decision ("I do/don't have X in my
// app"); the leaf is the addressable unit that emits decisions, carries a
// CWE list, and is named in audit logs and metrics. Some L1 families are
// flat — they have leaves directly with no L2 layer — when no situational
// distinction is meaningful. All three IDs are valid in config disable/
// enable lists; the resolver expands non-leaf IDs to their leaves.
//
// # Default-state philosophy
//
// A leaf is on by default iff (1) its false-positive rate at PL1 is low
// enough for general traffic and (2) a safe behavior exists when the
// detector misfires. Leaves that fail either test ship off. Why a given
// leaf is off by default — FP-prone variant, no safe default value,
// situational opt-in — is documented per leaf in WhyEnable; that prose,
// not a structural tier, is the canonical explanation.
//
// By convention, leaf IDs ending in "-aggressive" denote FP-prone
// variants gated off by default; this is a naming convention only and
// not load-bearing for the runtime.
//
// # Adding a new protection
//
// Append one Leaf to the appropriate L2 or flat L1, then ensure
// TestCatalogIntegrity still passes. See docs/design/conventions.md for
// the surrounding workflow (config defaults, tests, blackbox fixtures).
//
// # Reference output
//
// The full leaf list with WhatItDoes / WhyDisable / WhyEnable / CWE /
// RuleIDs is rendered by `barbacana --catalog` (or per-leaf via
// `barbacana --catalog-leaf <id>`). That render is the canonical reference
// for operators; this file is the canonical source for code.
package protections

// Default is a leaf's startup state.
type Default int

const (
	On Default = iota
	Off
)

func (d Default) String() string {
	switch d {
	case On:
		return "on"
	case Off:
		return "off"
	}
	return "unknown"
}

// Leaf is a single addressable protection.
type Leaf struct {
	// ID is the canonical identifier — the token developers type in disable:
	// and enable: lists, the value emitted as Decision.Protection, the
	// Prometheus label, and the audit-log field. Must start with the parent
	// Group.ID prefix.
	ID string

	// Default is the leaf's startup state (On or Off).
	Default Default

	// CWE is the list of applicable CWE IDs as integers. The audit emitter
	// formats these as "CWE-NNN" strings at output time.
	CWE []int

	// RuleIDs lists CRS rule numbers (as zero-padded strings) that contribute
	// to this leaf, or the literal "native" if the detection is implemented
	// in barbacana code rather than CRS.
	RuleIDs []string

	// WhatItDoes is a plain-language description of what the rule catches.
	// Required for every leaf.
	WhatItDoes string

	// WhyDisable is a situational explanation of when a developer would
	// legitimately disable this leaf. Required when Default == On.
	WhyDisable string

	// WhyEnable is a situational explanation of when a developer would
	// turn this leaf on. Required when Default == Off.
	WhyEnable string

	// Status is the HTTP status code emitted on a block. Zero (the
	// default) means 403 Forbidden — the universal block code. Set on
	// the small set of leaves whose blocks have a more specific status
	// (413 for oversized body, 431 for header limits, 405 for method
	// policy, 415 for content-type policy, 422 for OpenAPI body/param
	// mismatches, 404 for OpenAPI path-not-in-spec).
	//
	// Hardcoded per leaf today. Future configurability will likely
	// follow a per-route block-response override model (status + body +
	// headers as one unit), with this field as the fallback when no
	// override is configured. Do not split into per-leaf-per-route
	// override mechanics speculatively — the route-level override is
	// the right granularity, and the per-leaf default suffices until
	// that ships.
	Status int
}

// L2 is a situational bucket within a Group, corresponding to a real
// developer decision ("I do/don't have X in my app").
type L2 struct {
	ID          string
	Name        string // human-readable for docs
	Description string // L2-level prose; rendered above the leaf table
	WhyDisable  string // L2-level disable rationale
	Leaves      []Leaf
}

// Group is an L1 family.
type Group struct {
	ID          string
	Name        string
	Description string
	WhyDisable  string // L1-level disable rationale; required even when "risky; usually wrong"
	DocsRemark  string // optional; outline for a dedicated docs page (e.g., response-headers-add)
	Buckets     []L2   // L2 buckets if the family has internal structure
	Leaves      []Leaf // direct leaves if the family is flat (mutually exclusive with Buckets)
}

// Catalog is the full ordered list of L1 families. Sourced from
// .planning/protection_taxonomy_proposal.md verbatim.
var Catalog = catalogValue()

// leafEntry holds a leaf together with its containing L1 family and L2
// bucket (zero-value L2 for flat families). Stored as the value type of
// leafByID so LookupLeaf can return the same (leaf, group, bucket, ok)
// tuple it always has without re-walking the tree.
type leafEntry struct {
	Leaf   Leaf
	Group  Group
	Bucket L2
}

// Index views over Catalog. Built once at init from the tree, never
// mutated thereafter. The tree (Catalog) remains the declarative source
// — these are derived access shapes for the per-request hot path
// (leafByID) and for the startup-time accessors that previously
// re-walked the tree on every call.
var (
	indexes     = buildIndexes()
	leafByID    = indexes.byID
	leavesUnder = indexes.under
	allLeafIDs  = indexes.all
	configNames = indexes.names
)

type catalogIndexes struct {
	byID  map[string]leafEntry
	under map[string][]string
	all   []string
	names map[string]bool
}

// buildIndexes walks Catalog once and returns the four derived views
// used by the accessors below: a leaf-by-ID lookup for the per-request
// hot path (LookupLeaf, and through it CWEForProtection / StatusFor),
// a per-ID expansion map for config resolution (LeafIDsUnder), an
// ordered slice of every leaf ID (AllLeafIDs), and the set of all
// valid config identifiers — L1, L2, and leaf — for validation
// (ConfigNames). Catalog is immutable after init, so these indexes are
// safe to share without copying or locking.
func buildIndexes() catalogIndexes {
	idx := catalogIndexes{
		byID:  map[string]leafEntry{},
		under: map[string][]string{},
		names: map[string]bool{},
	}
	for _, g := range Catalog {
		idx.names[g.ID] = true
		var groupLeaves []string

		for _, l := range g.Leaves {
			idx.byID[l.ID] = leafEntry{Leaf: l, Group: g}
			idx.names[l.ID] = true
			idx.all = append(idx.all, l.ID)
			idx.under[l.ID] = []string{l.ID}
			groupLeaves = append(groupLeaves, l.ID)
		}

		for _, b := range g.Buckets {
			idx.names[b.ID] = true
			var bucketLeaves []string
			for _, l := range b.Leaves {
				idx.byID[l.ID] = leafEntry{Leaf: l, Group: g, Bucket: b}
				idx.names[l.ID] = true
				idx.all = append(idx.all, l.ID)
				idx.under[l.ID] = []string{l.ID}
				bucketLeaves = append(bucketLeaves, l.ID)
				groupLeaves = append(groupLeaves, l.ID)
			}
			idx.under[b.ID] = bucketLeaves
		}

		idx.under[g.ID] = groupLeaves
	}
	return idx
}

// CatalogStats summarizes the shape of Catalog. Returned by Stats() and
// asserted by invariant 12 of TestCatalogIntegrity against direct counts.
type CatalogStats struct {
	L1Families  int
	L2Buckets   int
	FlatL1s     int
	TotalLeaves int
	OnLeaves    int
	OffLeaves   int
}

// Stats computes CatalogStats from the live Catalog value.
func Stats() CatalogStats {
	var s CatalogStats
	s.L1Families = len(Catalog)
	for _, g := range Catalog {
		if len(g.Leaves) > 0 {
			s.FlatL1s++
			for _, l := range g.Leaves {
				s.TotalLeaves++
				if l.Default == On {
					s.OnLeaves++
				} else {
					s.OffLeaves++
				}
			}
		}
		s.L2Buckets += len(g.Buckets)
		for _, b := range g.Buckets {
			for _, l := range b.Leaves {
				s.TotalLeaves++
				if l.Default == On {
					s.OnLeaves++
				} else {
					s.OffLeaves++
				}
			}
		}
	}
	return s
}

// LookupLeaf returns the Leaf with the given ID and the L1/L2 path that
// contains it, or ok=false if no leaf matches.
func LookupLeaf(id string) (leaf Leaf, group Group, bucket L2, ok bool) {
	e, ok := leafByID[id]
	return e.Leaf, e.Group, e.Bucket, ok
}

// IsDisabled reports whether the given canonical name is in the
// disabled set. The disabled set is produced by config resolution at
// startup time. This is the per-request hot-path check.
func IsDisabled(name string, disabled map[string]bool) bool {
	return disabled[name]
}

// StatusFor returns the HTTP status code to write when the named
// protection blocks a request. Defaults to 403 Forbidden for any leaf
// without a Status set, and for unknown names. The Status field is
// populated on Leaf for the small set of leaves whose blocks should
// emit a more specific status (413 for body too large, 431 for header
// limits, 405 for method/path policy, 415 for content-type policy,
// 422 for OpenAPI body/param mismatches, 404 for OpenAPI path).
func StatusFor(name string) int {
	leaf, _, _, ok := LookupLeaf(name)
	if !ok || leaf.Status == 0 {
		return 403
	}
	return leaf.Status
}

// CWEForProtection returns the formatted "CWE-NNN" identifiers for the
// canonical leaf name, sourced from Catalog. Returns an empty slice if
// the name is unknown. The audit emitter accumulates these into
// Entry.CWE.
//
// Phase 4 of the taxonomy refactor: replaces the legacy single-string
// signature in legacy.go (deleted at end of phase 4). Reading from the
// catalog is order-independent — both addDecision and addNativeDecision
// resolve the same set regardless of which detector fired first, which
// closes the CWE-attribution gap surfaced by TestAuditCollectorReverseOrder.
func CWEForProtection(name string) []string {
	leaf, _, _, ok := LookupLeaf(name)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(leaf.CWE))
	for _, n := range leaf.CWE {
		out = append(out, formatCWEInt(n))
	}
	return out
}

// formatCWEInt converts a single CWE integer to its "CWE-NNN" form.
// Avoids a fmt dependency in the hot audit-emit path. The plural form
// formatCWE in render.go takes a slice and joins for table cells; this
// one is for the per-CWE accumulation in CWEForProtection.
func formatCWEInt(n int) string {
	if n == 0 {
		return "CWE-0"
	}
	digits := make([]byte, 0, 6)
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return "CWE-" + string(digits)
}

// ConfigNames returns the full set of valid identifiers a user may put
// in a route's `disable:` or `enable:` list: every L1 family ID, every
// L2 bucket ID, and every leaf ID. Phase 4: this is the post-refactor
// replacement for legacy.AllNames(), which consulted the deprecated
// two-level Protections slice.
func ConfigNames() map[string]bool {
	return configNames
}

// LeafIDsUnder returns the slice of leaf IDs reachable from the given
// L1 or L2 ID. Returns ok=false if the ID is unknown. A leaf ID maps to
// a single-element slice containing itself. Used by config resolution
// to expand `disable: [sql]` to every leaf under the SQL family.
func LeafIDsUnder(id string) (leaves []string, ok bool) {
	leaves, ok = leavesUnder[id]
	return leaves, ok
}

// AllLeafIDs returns every leaf ID in catalog order.
func AllLeafIDs() []string {
	return allLeafIDs
}
