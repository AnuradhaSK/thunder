// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package sharing

import (
	"context"
	"sync"

	"github.com/thunder-id/thunderid/internal/system/log"
)

const registryLoggerComponentName = "SharingRegistry"

// registry holds the declarations of every resource type onboarded onto the sharing framework.
// Mirrors the resourcedependency.Registry idiom: a small, self-registering set of declarations
// consulted generically by the engine, with optional capabilities (SharingHooks) discovered via
// type assertion rather than a separate registration call.
type registry struct {
	mu     sync.RWMutex
	decls  map[ResourceType]ResourceTypeDeclaration
	logger *log.Logger
}

// newRegistry creates an empty resource-type registry.
func newRegistry() *registry {
	return &registry{
		decls:  make(map[ResourceType]ResourceTypeDeclaration),
		logger: log.GetLogger().With(log.String(log.LoggerKeyComponentName, registryLoggerComponentName)),
	}
}

// register adds or replaces a resource type's declaration. A nil declaration is ignored so a
// service that failed to initialize cannot panic a later lookup.
func (r *registry) register(decl ResourceTypeDeclaration) {
	if decl == nil {
		r.logger.Warn(context.Background(), "Ignoring nil resource type declaration registration")
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.decls[decl.ResourceType()] = decl
}

// get returns the declaration registered for resourceType, if any.
func (r *registry) get(resourceType ResourceType) (ResourceTypeDeclaration, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	decl, ok := r.decls[resourceType]
	return decl, ok
}

// templatedField returns the declared TemplatedFieldDeclaration for resourceType/fieldKey.
func (r *registry) templatedField(resourceType ResourceType, fieldKey string) (TemplatedFieldDeclaration, bool) {
	decl, ok := r.get(resourceType)
	if !ok {
		return TemplatedFieldDeclaration{}, false
	}
	for _, f := range decl.TemplatedFields() {
		if f.Key == fieldKey {
			return f, true
		}
	}
	return TemplatedFieldDeclaration{}, false
}
