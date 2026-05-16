package protections

import (
	"context"
	"net/http"
)

// Protection is the interface every security check implements. The pipeline
// calls Evaluate for each registered protection whose canonical name is not
// in the route's disable set.
type Protection interface {
	Name() string
	Category() string
	CWE() string // e.g. "CWE-89", "" if not applicable
	Evaluate(ctx context.Context, r *http.Request) Decision
}

// Decision is the result of evaluating a single protection against a request.
//
// Status and CWE are optional carry-along metadata for config-driven features
// (e.g. rate limiting) that do not appear in the catalog. When non-zero/non-nil
// they take precedence over StatusFor / CWEForProtection. Catalog-managed
// protections leave both at the zero value and the pipeline falls back to the
// catalog as the single source of truth.
type Decision struct {
	Block        bool
	Protection   string   // canonical name that triggered
	Reason       string   // human-readable, debug log only
	MatchedRules []int    // CRS rule IDs that fired; empty for native protections
	Status       int      // HTTP status; 0 = use StatusFor(Protection)
	CWE          []string // pre-formatted CWE IDs (e.g. "CWE-400"); nil = use CWEForProtection(Protection)
}

// Allow returns a passing decision.
func Allow() Decision { return Decision{} }

// Block returns a blocking decision with the given protection name and reason.
func Block(name, reason string) Decision {
	return Decision{Block: true, Protection: name, Reason: reason}
}
