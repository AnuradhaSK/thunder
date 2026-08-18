// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	oupkg "github.com/thunder-id/thunderid/internal/ou"
	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
)

func TestOURoleResolver_GetRoleCountByOUID(t *testing.T) {
	t.Run("success, counts owned and shared", func(t *testing.T) {
		service := NewRoleServiceInterfaceMock(t)
		service.On("ListRolesForOU", context.Background(), "ou-1", 1, 0).
			Return(&RoleListForOU{TotalResults: 3}, nil).Once()

		resolver := newOURoleResolver(service)
		count, err := resolver.GetRoleCountByOUID(context.Background(), "ou-1")

		require.NoError(t, err)
		require.Equal(t, 3, count)
	})

	t.Run("service error", func(t *testing.T) {
		service := NewRoleServiceInterfaceMock(t)
		service.On("ListRolesForOU", context.Background(), "ou-1", 1, 0).
			Return(nil, &tidcommon.InternalServerError).Once()

		resolver := newOURoleResolver(service)
		count, err := resolver.GetRoleCountByOUID(context.Background(), "ou-1")

		require.Error(t, err)
		require.Equal(t, 0, count)
	})
}

func TestOURoleResolver_GetRoleListByOUID(t *testing.T) {
	t.Run("success, includes shared roles tagged by origin", func(t *testing.T) {
		service := NewRoleServiceInterfaceMock(t)
		service.On("ListRolesForOU", context.Background(), "ou-1", 10, 0).
			Return(&RoleListForOU{
				Roles: []RoleForOU{
					{
						Role:   Role{ID: "r1", Name: "Admin", Description: "Admin role", OUID: "ou-1"},
						Origin: RoleOriginOwned,
					},
					{
						Role: Role{
							ID: "r2", Name: "Shared Role", OUID: "ou-owner", OUHandle: "owner-handle", IsReadOnly: true,
						},
						Origin: RoleOriginShared,
					},
				},
			}, nil).Once()

		resolver := newOURoleResolver(service)
		roles, err := resolver.GetRoleListByOUID(context.Background(), "ou-1", 10, 0)

		require.NoError(t, err)
		require.Len(t, roles, 2)
		require.Equal(t, oupkg.Role{
			ID: "r1", Name: "Admin", Description: "Admin role", OUID: "ou-1", Origin: oupkg.RoleOriginOwned,
		}, roles[0])
		require.Equal(t, oupkg.Role{
			ID: "r2", Name: "Shared Role", OUID: "ou-owner", OUHandle: "owner-handle",
			IsReadOnly: true, Origin: oupkg.RoleOriginShared,
		}, roles[1])
	})

	t.Run("service error", func(t *testing.T) {
		service := NewRoleServiceInterfaceMock(t)
		service.On("ListRolesForOU", context.Background(), "ou-1", 10, 0).
			Return(nil, &tidcommon.InternalServerError).Once()

		resolver := newOURoleResolver(service)
		roles, err := resolver.GetRoleListByOUID(context.Background(), "ou-1", 10, 0)

		require.Error(t, err)
		require.Nil(t, roles)
	})

	t.Run("empty results", func(t *testing.T) {
		service := NewRoleServiceInterfaceMock(t)
		service.On("ListRolesForOU", context.Background(), "ou-1", 10, 0).
			Return(&RoleListForOU{Roles: []RoleForOU{}}, nil).Once()

		resolver := newOURoleResolver(service)
		roles, err := resolver.GetRoleListByOUID(context.Background(), "ou-1", 10, 0)

		require.NoError(t, err)
		require.NotNil(t, roles)
		require.Empty(t, roles)
	})
}
