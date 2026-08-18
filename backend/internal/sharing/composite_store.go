// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package sharing

import (
	"context"
	"errors"
)

// compositeSharingStore serves grants from both the database and the declarative (in-memory)
// store, mirroring the composite-store idiom each declarative-capable resource type already uses
// for the resources themselves.
//
// Reads merge the two, database grants first, so a deployment that mixes declaratively defined
// resources with database-backed ones resolves visibility across both. Writes only ever reach the
// database: a declarative grant belongs to its file, so it is created by seeding at load time and
// removed by editing the file, never through the API.
type compositeSharingStore struct {
	dbStore          sharingStoreInterface
	declarativeStore *declarativeGrantStore
}

// newCompositeSharingStore composes a database store with the declarative grant store.
func newCompositeSharingStore(
	dbStore sharingStoreInterface, declarativeStore *declarativeGrantStore,
) *compositeSharingStore {
	return &compositeSharingStore{dbStore: dbStore, declarativeStore: declarativeStore}
}

// CreateGrant persists to the database. Declarative grants never take this path; they are seeded
// directly into the declarative store while resources are loading.
func (c *compositeSharingStore) CreateGrant(ctx context.Context, grant Grant) error {
	return c.dbStore.CreateGrant(ctx, grant)
}

// GetGrant reads from the database, falling back to the declarative store.
func (c *compositeSharingStore) GetGrant(ctx context.Context, id string) (Grant, error) {
	grant, err := c.dbStore.GetGrant(ctx, id)
	if err == nil {
		return grant, nil
	}
	if !errors.Is(err, ErrGrantNotFound) {
		return Grant{}, err
	}
	if declared, found := c.declarativeStore.GetGrant(id); found {
		return declared, nil
	}
	return Grant{}, ErrGrantNotFound
}

// DeleteGrant removes a database grant. A declaratively declared grant is refused: it exists for
// as long as the file that declares it does, and deleting it here would resurrect it on the next
// startup while leaving the running process disagreeing with the file in the meantime.
func (c *compositeSharingStore) DeleteGrant(ctx context.Context, id string) error {
	if c.declarativeStore.Has(id) {
		return ErrGrantDeclarative
	}
	return c.dbStore.DeleteGrant(ctx, id)
}

// ListGrantsForResource merges both sources.
func (c *compositeSharingStore) ListGrantsForResource(
	ctx context.Context, resourceType ResourceType, resourceID string,
) ([]Grant, error) {
	dbGrants, err := c.dbStore.ListGrantsForResource(ctx, resourceType, resourceID)
	if err != nil {
		return nil, err
	}
	return append(dbGrants, c.declarativeStore.ListGrantsForResource(resourceType, resourceID)...), nil
}

// ListGrantsForResourcePage pages over the merged set. The database store cannot page across a
// second source, so the merge happens here and the page is cut from the combined slice; the
// ordering database grants first, then declared ones in declaration order, is stable across calls,
// which is what pagination requires.
func (c *compositeSharingStore) ListGrantsForResourcePage(
	ctx context.Context, resourceType ResourceType, resourceID string, limit, offset int,
) ([]Grant, error) {
	all, err := c.ListGrantsForResource(ctx, resourceType, resourceID)
	if err != nil {
		return nil, err
	}
	if offset >= len(all) {
		return []Grant{}, nil
	}
	end := offset + limit
	if limit <= 0 || end > len(all) {
		end = len(all)
	}
	return all[offset:end], nil
}

// CountGrantsForResource counts both sources.
func (c *compositeSharingStore) CountGrantsForResource(
	ctx context.Context, resourceType ResourceType, resourceID string,
) (int, error) {
	dbCount, err := c.dbStore.CountGrantsForResource(ctx, resourceType, resourceID)
	if err != nil {
		return 0, err
	}
	return dbCount + len(c.declarativeStore.ListGrantsForResource(resourceType, resourceID)), nil
}

// ListChildGrants merges both sources.
func (c *compositeSharingStore) ListChildGrants(ctx context.Context, parentGrantID string) ([]Grant, error) {
	dbGrants, err := c.dbStore.ListChildGrants(ctx, parentGrantID)
	if err != nil {
		return nil, err
	}
	return append(dbGrants, c.declarativeStore.ListChildGrants(parentGrantID)...), nil
}

// ListGrantsRelevantToChain merges both sources, so a declaratively declared grant participates in
// visibility resolution exactly as a persisted one does.
func (c *compositeSharingStore) ListGrantsRelevantToChain(
	ctx context.Context, resourceType ResourceType, chainOUIDs []string,
) ([]Grant, error) {
	dbGrants, err := c.dbStore.ListGrantsRelevantToChain(ctx, resourceType, chainOUIDs)
	if err != nil {
		return nil, err
	}
	return append(dbGrants, c.declarativeStore.ListGrantsRelevantToChain(resourceType, chainOUIDs)...), nil
}

// GetOverlay, SetOverlay and DeleteOverlay pass straight through to the database. An overlay is a
// sharee organization unit's own runtime edit of a templated field, not part of what the file
// declares, so it is persisted even when the resource and its grants are declarative.
func (c *compositeSharingStore) GetOverlay(
	ctx context.Context, resourceType ResourceType, resourceID, ouID string,
) (map[string]string, bool, error) {
	return c.dbStore.GetOverlay(ctx, resourceType, resourceID, ouID)
}

func (c *compositeSharingStore) SetOverlay(
	ctx context.Context, resourceType ResourceType, resourceID, ouID string, fields map[string]string,
) error {
	return c.dbStore.SetOverlay(ctx, resourceType, resourceID, ouID, fields)
}

func (c *compositeSharingStore) DeleteOverlay(
	ctx context.Context, resourceType ResourceType, resourceID, ouID string,
) error {
	return c.dbStore.DeleteOverlay(ctx, resourceType, resourceID, ouID)
}
