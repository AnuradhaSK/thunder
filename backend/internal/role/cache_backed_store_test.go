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

// CacheBackedRoleStoreTestSuite covers cacheBackedRoleStore's point-invalidation behavior: writes
// that affect potentially many roles at once (DeleteRolePermission, DeleteRolePermissionForOU)
// must invalidate every affected cache entry, not just pass through to the underlying store —
// otherwise a subsequent GetRole can return a stale, already-deleted permission.
type CacheBackedRoleStoreTestSuite struct {
	suite.Suite
	mockStore *roleStoreInterfaceMock
	mockCache *cachemock.CacheInterfaceMock[*RoleWithPermissions]
	store     roleStoreInterface
}

func TestCacheBackedRoleStoreTestSuite(t *testing.T) {
	suite.Run(t, new(CacheBackedRoleStoreTestSuite))
}

func (suite *CacheBackedRoleStoreTestSuite) SetupTest() {
	suite.mockStore = newRoleStoreInterfaceMock(suite.T())
	suite.mockCache = cachemock.NewCacheInterfaceMock[*RoleWithPermissions](suite.T())
	suite.store = newCacheBackedRoleStore(suite.mockStore, suite.mockCache)
}

func (suite *CacheBackedRoleStoreTestSuite) TestDeleteRolePermission_ClearsCacheWhenRowsDeleted() {
	suite.mockStore.On("DeleteRolePermission", mock.Anything, "rs1", "read").Return(int64(3), nil)
	suite.mockCache.On("Clear", mock.Anything).Return(nil)

	deleted, err := suite.store.DeleteRolePermission(context.Background(), "rs1", "read")

	suite.NoError(err)
	suite.Equal(int64(3), deleted)
}

func (suite *CacheBackedRoleStoreTestSuite) TestDeleteRolePermission_NoClearWhenNothingDeleted() {
	suite.mockStore.On("DeleteRolePermission", mock.Anything, "rs1", "read").Return(int64(0), nil)

	deleted, err := suite.store.DeleteRolePermission(context.Background(), "rs1", "read")

	suite.NoError(err)
	suite.Equal(int64(0), deleted)
	suite.mockCache.AssertNotCalled(suite.T(), "Clear", mock.Anything)
}

func (suite *CacheBackedRoleStoreTestSuite) TestDeleteRolePermission_StoreErrorSkipsClear() {
	suite.mockStore.On("DeleteRolePermission", mock.Anything, "rs1", "read").
		Return(int64(0), errors.New("db error"))

	deleted, err := suite.store.DeleteRolePermission(context.Background(), "rs1", "read")

	suite.Error(err)
	suite.Equal(int64(0), deleted)
	suite.mockCache.AssertNotCalled(suite.T(), "Clear", mock.Anything)
}

func (suite *CacheBackedRoleStoreTestSuite) TestDeleteRolePermissionForOU_InvalidatesAffectedRoles() {
	suite.mockStore.On("DeleteRolePermissionForOU", mock.Anything, "ou1", "rs1", "books:create").
		Return(int64(2), nil)
	suite.mockStore.On("GetRoleListCountByOUID", mock.Anything, "ou1").Return(2, nil)
	suite.mockStore.On("GetRoleListByOUID", mock.Anything, "ou1", 2, 0).Return([]Role{
		{ID: "role1"}, {ID: "role2"},
	}, nil)
	suite.mockCache.On("Delete", mock.Anything, cache.CacheKey{Key: "role1"}).Return(nil)
	suite.mockCache.On("Delete", mock.Anything, cache.CacheKey{Key: "role2"}).Return(nil)

	deleted, err := suite.store.DeleteRolePermissionForOU(context.Background(), "ou1", "rs1", "books:create")

	suite.NoError(err)
	suite.Equal(int64(2), deleted)
}

func (suite *CacheBackedRoleStoreTestSuite) TestDeleteRolePermissionForOU_NoInvalidationWhenNothingDeleted() {
	suite.mockStore.On("DeleteRolePermissionForOU", mock.Anything, "ou1", "rs1", "books:create").
		Return(int64(0), nil)

	deleted, err := suite.store.DeleteRolePermissionForOU(context.Background(), "ou1", "rs1", "books:create")

	suite.NoError(err)
	suite.Equal(int64(0), deleted)
	suite.mockStore.AssertNotCalled(suite.T(), "GetRoleListCountByOUID", mock.Anything, mock.Anything)
}

func (suite *CacheBackedRoleStoreTestSuite) TestDeleteRolePermissionForOU_StoreErrorSkipsInvalidation() {
	suite.mockStore.On("DeleteRolePermissionForOU", mock.Anything, "ou1", "rs1", "books:create").
		Return(int64(0), errors.New("db error"))

	deleted, err := suite.store.DeleteRolePermissionForOU(context.Background(), "ou1", "rs1", "books:create")

	suite.Error(err)
	suite.Equal(int64(0), deleted)
	suite.mockStore.AssertNotCalled(suite.T(), "GetRoleListCountByOUID", mock.Anything, mock.Anything)
}

func (suite *CacheBackedRoleStoreTestSuite) TestDeleteRolePermissionForOU_CountErrorIsLoggedNotPropagated() {
	// Cache invalidation failures must never fail the caller: the permission is already deleted at
	// this point, and the cache will simply serve stale data until it naturally expires/evicts.
	suite.mockStore.On("DeleteRolePermissionForOU", mock.Anything, "ou1", "rs1", "books:create").
		Return(int64(1), nil)
	suite.mockStore.On("GetRoleListCountByOUID", mock.Anything, "ou1").Return(0, errors.New("db error"))

	deleted, err := suite.store.DeleteRolePermissionForOU(context.Background(), "ou1", "rs1", "books:create")

	suite.NoError(err)
	suite.Equal(int64(1), deleted)
}

func (suite *CacheBackedRoleStoreTestSuite) TestGetRole_ServesFromCacheWhenPresent() {
	cached := &RoleWithPermissions{ID: "role1", Name: "Cached"}
	suite.mockCache.On("Get", mock.Anything, cache.CacheKey{Key: "role1"}).Return(cached, true)

	role, err := suite.store.GetRole(context.Background(), "role1")

	suite.NoError(err)
	suite.Equal("Cached", role.Name)
	suite.mockStore.AssertNotCalled(suite.T(), "GetRole", mock.Anything, mock.Anything)
}

func (suite *CacheBackedRoleStoreTestSuite) TestGetRole_FallsBackToStoreAndCachesResult() {
	suite.mockCache.On("Get", mock.Anything, cache.CacheKey{Key: "role1"}).Return((*RoleWithPermissions)(nil), false)
	suite.mockStore.On("GetRole", mock.Anything, "role1").
		Return(RoleWithPermissions{ID: "role1", Name: "FromStore"}, nil)
	suite.mockCache.On("Set", mock.Anything, cache.CacheKey{Key: "role1"}, mock.Anything).Return(nil)

	role, err := suite.store.GetRole(context.Background(), "role1")

	suite.NoError(err)
	suite.Equal("FromStore", role.Name)
}

// TestGetRole_ServesFreshRoleAfterPermissionDeletion is the end-to-end shape of the defect the
// clear above fixes: read a role (populating the cache), strip one of its permissions through the
// cascade, then read it again and get the post-deletion row rather than the cached one.
func (suite *CacheBackedRoleStoreTestSuite) TestGetRole_ServesFreshRoleAfterPermissionDeletion() {
	key := cache.CacheKey{Key: "role1"}
	withPermission := RoleWithPermissions{
		ID: "role1", OUID: "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"res:action"}}},
	}
	withoutPermission := RoleWithPermissions{
		ID: "role1", OUID: "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{}}},
	}

	suite.mockCache.On("Get", mock.Anything, key).Return((*RoleWithPermissions)(nil), false).Once()
	suite.mockStore.On("GetRole", mock.Anything, "role1").Return(withPermission, nil).Once()
	suite.mockCache.On("Set", mock.Anything, key, mock.Anything).Return(nil)

	first, err := suite.store.GetRole(context.Background(), "role1")
	suite.Require().NoError(err)
	suite.Equal([]string{"res:action"}, first.Permissions[0].Permissions)

	suite.mockStore.On("DeleteRolePermission", mock.Anything, "rs1", "res:action").Return(int64(1), nil)
	suite.mockCache.On("Clear", mock.Anything).Return(nil)
	_, err = suite.store.DeleteRolePermission(context.Background(), "rs1", "res:action")
	suite.Require().NoError(err)

	// The clear happened, so the next read misses and goes back to the store.
	suite.mockCache.On("Get", mock.Anything, key).Return((*RoleWithPermissions)(nil), false).Once()
	suite.mockStore.On("GetRole", mock.Anything, "role1").Return(withoutPermission, nil).Once()

	second, err := suite.store.GetRole(context.Background(), "role1")
	suite.Require().NoError(err)
	suite.Empty(second.Permissions[0].Permissions)
}
