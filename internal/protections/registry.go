package protections

import (
	"fmt"
	"sync"
)

// Registry holds all registered protections and provides lookup by canonical
// name. Constructed in main, passed to the pipeline. Immutable after startup.
type Registry struct {
	mu          sync.RWMutex
	protections map[string]Protection  // canonical name → protection
	categories  map[string][]string    // category name → sub-protection names
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		protections: make(map[string]Protection),
		categories:  make(map[string][]string),
	}
}

// Add registers a protection. If the protection has a non-empty Category(),
// it is recorded as a sub-protection of that category. Panics on duplicate
// name — this is a startup-time error, not a request-time error.
func (reg *Registry) Add(p Protection) {
	reg.mu.Lock()
	defer reg.mu.Unlock()

	name := p.Name()
	if _, exists := reg.protections[name]; exists {
		panic(fmt.Sprintf("duplicate protection registration: %q", name))
	}
	reg.protections[name] = p
	if cat := p.Category(); cat != "" {
		reg.categories[cat] = append(reg.categories[cat], name)
	}
}

// Get returns the protection with the given canonical name, or nil.
func (reg *Registry) Get(name string) Protection {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	return reg.protections[name]
}

// All returns every registered protection in no guaranteed order.
func (reg *Registry) All() []Protection {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	out := make([]Protection, 0, len(reg.protections))
	for _, p := range reg.protections {
		out = append(out, p)
	}
	return out
}

// SubProtections returns the sub-protection names under a category, or nil
// if the name is not a registered category.
func (reg *Registry) SubProtections(category string) []string {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	return reg.categories[category]
}

// IsDisabled reports whether the given canonical name is in the disabled set.
// The disabled set should be produced by ExpandDisable at config resolution
// time. This is the per-request hot-path check.
func IsDisabled(name string, disabled map[string]bool) bool {
	return disabled[name]
}
