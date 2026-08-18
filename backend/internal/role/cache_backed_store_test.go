// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/system/cache"
	"github.com/thunder-id/thunderid/tests/mocks/cachemock"
)

type CacheBackedRoleStoreTestSuite struct {
	suite.Suite
	mockInner   *roleStoreInterfaceMock
	roleCache   *cachemock.CacheInterfaceMock[*RoleWithPermissions]
	cachedStore roleStoreInterface
}

func TestCacheBackedRoleStoreTestSuite(t *testing.T) {
	suite.Run(t, new(CacheBackedRoleStoreTestSuite))
}

func (s *CacheBackedRoleStoreTestSuite) SetupTest() {
	s.mockInner = newRoleStoreInterfaceMock(s.T())
	s.roleCache = cachemock.NewCacheInterfaceMock[*RoleWithPermissions](s.T())
	s.cachedStore = newCacheBackedRoleStore(s.mockInner, s.roleCache)
}

// TestDeleteRolePermission_ClearsCache proves the cascade that strips a deleted resource's
// permission from every role also drops the cached roles. A cached RoleWithPermissions carries its
// permission list, and this deletion spans roles whose ids are not known here, so a point
// invalidation is impossible and skipping it would keep serving the deleted permission.
func (s *CacheBackedRoleStoreTestSuite) TestDeleteRolePermission_ClearsCache() {
	s.mockInner.On("DeleteRolePermission", mock.Anything, "rs1", "res:action").Return(int64(2), nil)
	s.roleCache.On("Clear", mock.Anything).Return(nil)

	deleted, err := s.cachedStore.DeleteRolePermission(context.Background(), "rs1", "res:action")

	s.NoError(err)
	s.Equal(int64(2), deleted)
	s.roleCache.AssertCalled(s.T(), "Clear", mock.Anything)
}

// TestDeleteRolePermission_NoRowsLeavesCacheAlone proves a deletion that matched nothing does not
// throw away every cached role for no reason.
func (s *CacheBackedRoleStoreTestSuite) TestDeleteRolePermission_NoRowsLeavesCacheAlone() {
	s.mockInner.On("DeleteRolePermission", mock.Anything, "rs1", "res:action").Return(int64(0), nil)

	deleted, err := s.cachedStore.DeleteRolePermission(context.Background(), "rs1", "res:action")

	s.NoError(err)
	s.Equal(int64(0), deleted)
	s.roleCache.AssertNotCalled(s.T(), "Clear", mock.Anything)
}

// TestDeleteRolePermission_StoreErrorLeavesCacheAlone proves a failed deletion does not clear the
// cache: nothing changed underneath it.
func (s *CacheBackedRoleStoreTestSuite) TestDeleteRolePermission_StoreErrorLeavesCacheAlone() {
	s.mockInner.On("DeleteRolePermission", mock.Anything, "rs1", "res:action").
		Return(int64(0), errors.New("db error"))

	_, err := s.cachedStore.DeleteRolePermission(context.Background(), "rs1", "res:action")

	s.Error(err)
	s.roleCache.AssertNotCalled(s.T(), "Clear", mock.Anything)
}

// TestGetRole_ServesFreshRoleAfterPermissionDeletion is the end-to-end shape of the defect the
// clear above fixes: read a role (populating the cache), strip one of its permissions through the
// cascade, then read it again and get the post-deletion row rather than the cached one.
func (s *CacheBackedRoleStoreTestSuite) TestGetRole_ServesFreshRoleAfterPermissionDeletion() {
	key := cache.CacheKey{Key: "role1"}
	withPermission := RoleWithPermissions{
		ID: "role1", OUID: "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"res:action"}}},
	}
	withoutPermission := RoleWithPermissions{
		ID: "role1", OUID: "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{}}},
	}

	s.roleCache.On("Get", mock.Anything, key).Return((*RoleWithPermissions)(nil), false).Once()
	s.mockInner.On("GetRole", mock.Anything, "role1").Return(withPermission, nil).Once()
	s.roleCache.On("Set", mock.Anything, key, mock.Anything).Return(nil)

	first, err := s.cachedStore.GetRole(context.Background(), "role1")
	s.Require().NoError(err)
	s.Equal([]string{"res:action"}, first.Permissions[0].Permissions)

	s.mockInner.On("DeleteRolePermission", mock.Anything, "rs1", "res:action").Return(int64(1), nil)
	s.roleCache.On("Clear", mock.Anything).Return(nil)
	_, err = s.cachedStore.DeleteRolePermission(context.Background(), "rs1", "res:action")
	s.Require().NoError(err)

	// The clear happened, so the next read misses and goes back to the store.
	s.roleCache.On("Get", mock.Anything, key).Return((*RoleWithPermissions)(nil), false).Once()
	s.mockInner.On("GetRole", mock.Anything, "role1").Return(withoutPermission, nil).Once()

	second, err := s.cachedStore.GetRole(context.Background(), "role1")
	s.Require().NoError(err)
	s.Empty(second.Permissions[0].Permissions)
}
