// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package sharing

import (
	"context"
	"sync"
)

// declarativeGrantStore holds the grants of declaratively defined resources in memory, for the
// lifetime of the process. A declarative resource lives in its own file-backed store and is never
// written to the database, so neither are its grants: the file is the sole source of truth for
// both, and persisting the grants alone would leave rows behind whenever the file changed, while
// replaying them on the next startup appended a duplicate of every one.
//
// Seeded once during declarative resource loading, through Seed, and read-only afterwards. It
// implements only the read half of sharingStoreInterface that compositeSharingStore delegates to;
// every mutation stays with the database store.
type declarativeGrantStore struct {
	mu sync.RWMutex
	// grants is kept as a slice rather than a map so that reads preserve seeding order, which is
	// the order the grants were declared in. The database store orders by CREATED_AT, so a
	// declared grant reads back in its declared position either way.
	grants []Grant
}

// newDeclarativeGrantStore creates an empty declarative grant store.
func newDeclarativeGrantStore() *declarativeGrantStore {
	return &declarativeGrantStore{}
}

// Seed records a grant. Called only while declarative resources are loading.
func (d *declarativeGrantStore) Seed(grant Grant) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.grants = append(d.grants, grant)
}

// Has reports whether id names a declaratively declared grant. Used to refuse mutations of one.
func (d *declarativeGrantStore) Has(id string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, grant := range d.grants {
		if grant.ID == id {
			return true
		}
	}
	return false
}

// GetGrant returns the grant with the given id, and whether it was found.
func (d *declarativeGrantStore) GetGrant(id string) (Grant, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, grant := range d.grants {
		if grant.ID == id {
			return grant, true
		}
	}
	return Grant{}, false
}

// ListGrantsForResource returns every declared grant for one resource.
func (d *declarativeGrantStore) ListGrantsForResource(resourceType ResourceType, resourceID string) []Grant {
	return d.filter(func(grant Grant) bool {
		return grant.ResourceType == resourceType && grant.ResourceID == resourceID
	})
}

// ListChildGrants returns every declared grant that reshares parentGrantID.
func (d *declarativeGrantStore) ListChildGrants(parentGrantID string) []Grant {
	return d.filter(func(grant Grant) bool {
		return grant.ParentGrantID == parentGrantID
	})
}

// ListGrantsRelevantToChain mirrors the store method of the same name: every declared grant of
// resourceType that either targets any root (so it can apply to any chain) or targets one of
// chainOUIDs. Coverage itself is still evaluated by the caller, in memory, exactly as it is for
// database grants.
func (d *declarativeGrantStore) ListGrantsRelevantToChain(
	resourceType ResourceType, chainOUIDs []string,
) []Grant {
	chain := make(map[string]struct{}, len(chainOUIDs))
	for _, ouID := range chainOUIDs {
		chain[ouID] = struct{}{}
	}
	return d.filter(func(grant Grant) bool {
		if grant.ResourceType != resourceType {
			return false
		}
		if grant.TargetScope == TargetScopeAllRoots {
			return true
		}
		_, inChain := chain[grant.TargetOUID]
		return inChain
	})
}

// declarativeLoadMarker marks a context as belonging to declarative resource loading, so that a
// grant created under it is seeded into the declarative store rather than persisted. It is set in
// exactly one place, ShareDeclarative, and never crosses an API or process boundary: it exists so
// that a declared grant passes through the identical validation Share() applies, instead of a
// parallel code path that could drift from it.
type declarativeLoadMarker struct{}

// withDeclarativeLoad marks ctx as a declarative load.
func withDeclarativeLoad(ctx context.Context) context.Context {
	return context.WithValue(ctx, declarativeLoadMarker{}, true)
}

// isDeclarativeLoad reports whether ctx was marked by withDeclarativeLoad.
func isDeclarativeLoad(ctx context.Context) bool {
	marked, ok := ctx.Value(declarativeLoadMarker{}).(bool)
	return ok && marked
}

// filter returns every grant satisfying keep, in seeding order.
func (d *declarativeGrantStore) filter(keep func(Grant) bool) []Grant {
	d.mu.RLock()
	defer d.mu.RUnlock()
	matched := make([]Grant, 0, len(d.grants))
	for _, grant := range d.grants {
		if keep(grant) {
			matched = append(matched, grant)
		}
	}
	return matched
}
