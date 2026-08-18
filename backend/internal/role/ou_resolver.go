// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"context"
	"errors"

	oupkg "github.com/thunder-id/thunderid/internal/ou"
)

// ouRoleResolverAdapter implements oupkg.OURoleResolver using RoleServiceInterface. This adapter
// allows the OU package to query role data (including roles shared into the OU, not just roles it
// owns) without directly accessing the ROLE table, breaking the cross-DB access boundary.
type ouRoleResolverAdapter struct {
	service RoleServiceInterface
}

// newOURoleResolver creates a new OURoleResolver backed by the given role service.
func newOURoleResolver(service RoleServiceInterface) oupkg.OURoleResolver {
	return &ouRoleResolverAdapter{service: service}
}

// GetRoleCountByOUID returns the count of roles visible to the given organization unit: those it
// owns plus those shared (directly or via reshare) to it.
func (a *ouRoleResolverAdapter) GetRoleCountByOUID(ctx context.Context, ouID string) (int, error) {
	// ListRolesForOU has no cheaper count-only path: an accurate total must resolve shared role
	// IDs and skip any stale grant pointing at a deleted role, the same work listing needs.
	list, svcErr := a.service.ListRolesForOU(ctx, ouID, 1, 0)
	if svcErr != nil {
		return 0, errors.New(svcErr.Error.DefaultValue)
	}
	return list.TotalResults, nil
}

// GetRoleListByOUID returns a paginated list of roles visible to the given organization unit
// (owned or shared), each tagged with its origin.
func (a *ouRoleResolverAdapter) GetRoleListByOUID(
	ctx context.Context, ouID string, limit, offset int,
) ([]oupkg.Role, error) {
	list, svcErr := a.service.ListRolesForOU(ctx, ouID, limit, offset)
	if svcErr != nil {
		return nil, errors.New(svcErr.Error.DefaultValue)
	}

	result := make([]oupkg.Role, len(list.Roles))
	for i, r := range list.Roles {
		result[i] = oupkg.Role{
			ID:          r.ID,
			Name:        r.Name,
			Description: r.Description,
			IsReadOnly:  r.IsReadOnly,
			OUID:        r.OUID,
			OUHandle:    r.OUHandle,
			Origin:      r.Origin,
		}
	}

	return result, nil
}
