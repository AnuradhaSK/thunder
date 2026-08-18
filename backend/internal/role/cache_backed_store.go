// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"context"

	"github.com/thunder-id/thunderid/internal/system/cache"
	"github.com/thunder-id/thunderid/internal/system/log"
)

// cacheBackedRoleStore wraps a roleStoreInterface with in-memory caching for individual role
// lookups by ID (core config + permissions). Following the cache_backed_store.go idiom used by
// ou/idp/entity/etc., point lookups are cached and point-invalidated on write; list/assignment
// operations are pass-throughs — assignment reads/writes are already OU-scoped point lookups
// handled by role's own store, and resolving shared-role visibility is cached separately by the
// sharing package.
type cacheBackedRoleStore struct {
	roleByIDCache cache.CacheInterface[*RoleWithPermissions]
	store         roleStoreInterface
	logger        *log.Logger
}

// newCacheBackedRoleStore creates a cache-backed wrapper around the given store.
func newCacheBackedRoleStore(
	store roleStoreInterface, roleByIDCache cache.CacheInterface[*RoleWithPermissions],
) roleStoreInterface {
	return &cacheBackedRoleStore{
		roleByIDCache: roleByIDCache,
		store:         store,
		logger:        log.GetLogger().With(log.String(log.LoggerKeyComponentName, "CacheBackedRoleStore")),
	}
}

func (s *cacheBackedRoleStore) GetRole(ctx context.Context, id string) (RoleWithPermissions, error) {
	cacheKey := cache.CacheKey{Key: id}
	if cached, ok := s.roleByIDCache.Get(ctx, cacheKey); ok && cached != nil {
		return *cached, nil
	}

	role, err := s.store.GetRole(ctx, id)
	if err != nil {
		return role, err
	}

	if err := s.roleByIDCache.Set(ctx, cacheKey, &role); err != nil {
		s.logger.Error(ctx, "Failed to cache role by ID", log.String("id", id), log.Error(err))
	}
	return role, nil
}

func (s *cacheBackedRoleStore) UpdateRole(ctx context.Context, id string, role RoleUpdateDetail) error {
	if err := s.store.UpdateRole(ctx, id, role); err != nil {
		return err
	}
	s.invalidate(ctx, id)
	return nil
}

func (s *cacheBackedRoleStore) DeleteRole(ctx context.Context, id string) error {
	if err := s.store.DeleteRole(ctx, id); err != nil {
		return err
	}
	s.invalidate(ctx, id)
	return nil
}

func (s *cacheBackedRoleStore) invalidate(ctx context.Context, id string) {
	if err := s.roleByIDCache.Delete(ctx, cache.CacheKey{Key: id}); err != nil {
		s.logger.Error(ctx, "Failed to invalidate role cache by ID", log.String("id", id), log.Error(err))
	}
}

// Pass-through methods.

func (s *cacheBackedRoleStore) GetRoleListCount(ctx context.Context) (int, error) {
	return s.store.GetRoleListCount(ctx)
}

func (s *cacheBackedRoleStore) GetRoleList(ctx context.Context, limit, offset int) ([]Role, error) {
	return s.store.GetRoleList(ctx, limit, offset)
}

func (s *cacheBackedRoleStore) GetRoleListCountByOUID(ctx context.Context, ouID string) (int, error) {
	return s.store.GetRoleListCountByOUID(ctx, ouID)
}

func (s *cacheBackedRoleStore) GetRoleListByOUID(ctx context.Context, ouID string, limit, offset int) ([]Role, error) {
	return s.store.GetRoleListByOUID(ctx, ouID, limit, offset)
}

func (s *cacheBackedRoleStore) CreateRole(ctx context.Context, id string, role RoleCreationDetail) error {
	return s.store.CreateRole(ctx, id, role)
}

func (s *cacheBackedRoleStore) IsRoleExist(ctx context.Context, id string) (bool, error) {
	return s.store.IsRoleExist(ctx, id)
}

func (s *cacheBackedRoleStore) GetRoleAssignments(
	ctx context.Context, id, ouID string, limit, offset int,
) ([]RoleAssignment, error) {
	return s.store.GetRoleAssignments(ctx, id, ouID, limit, offset)
}

func (s *cacheBackedRoleStore) GetRoleAssignmentsByType(
	ctx context.Context, id, ouID string, limit, offset int, assigneeType string,
) ([]RoleAssignment, error) {
	return s.store.GetRoleAssignmentsByType(ctx, id, ouID, limit, offset, assigneeType)
}

func (s *cacheBackedRoleStore) GetRoleAssignmentsCount(ctx context.Context, id, ouID string) (int, error) {
	return s.store.GetRoleAssignmentsCount(ctx, id, ouID)
}

func (s *cacheBackedRoleStore) GetRoleAssignmentsCountByType(
	ctx context.Context, id, ouID string, assigneeType string,
) (int, error) {
	return s.store.GetRoleAssignmentsCountByType(ctx, id, ouID, assigneeType)
}

func (s *cacheBackedRoleStore) DeleteAssignmentsByRoleID(ctx context.Context, id string) error {
	return s.store.DeleteAssignmentsByRoleID(ctx, id)
}

func (s *cacheBackedRoleStore) DeleteAssignmentsByAssignee(
	ctx context.Context, assigneeType, assigneeID string) (int64, error) {
	return s.store.DeleteAssignmentsByAssignee(ctx, assigneeType, assigneeID)
}

func (s *cacheBackedRoleStore) DeleteAssignmentsByOUID(ctx context.Context, id, ouID string) error {
	return s.store.DeleteAssignmentsByOUID(ctx, id, ouID)
}

func (s *cacheBackedRoleStore) AddAssignments(
	ctx context.Context, id, ouID string, assignments []RoleAssignment) error {
	return s.store.AddAssignments(ctx, id, ouID, assignments)
}

func (s *cacheBackedRoleStore) GetAssigningOUIDs(ctx context.Context, id string) ([]string, error) {
	return s.store.GetAssigningOUIDs(ctx, id)
}

func (s *cacheBackedRoleStore) RemoveAssignments(
	ctx context.Context, id, ouID string, assignments []RoleAssignment) error {
	return s.store.RemoveAssignments(ctx, id, ouID, assignments)
}

func (s *cacheBackedRoleStore) CheckRoleNameExists(ctx context.Context, ouID, name string) (bool, error) {
	return s.store.CheckRoleNameExists(ctx, ouID, name)
}

func (s *cacheBackedRoleStore) CheckRoleNameExistsExcludingID(
	ctx context.Context, ouID, name, excludeRoleID string) (bool, error) {
	return s.store.CheckRoleNameExistsExcludingID(ctx, ouID, name, excludeRoleID)
}

func (s *cacheBackedRoleStore) GetAuthorizedPermissionsByResourceServer(
	ctx context.Context, entityID string, groupIDs []string, resourceServerID string,
	requestedPermissions []string, ouID string,
) ([]string, error) {
	return s.store.GetAuthorizedPermissionsByResourceServer(
		ctx, entityID, groupIDs, resourceServerID, requestedPermissions, ouID)
}

func (s *cacheBackedRoleStore) GetUserRoles(ctx context.Context, entityID string, groupIDs []string) ([]string, error) {
	return s.store.GetUserRoles(ctx, entityID, groupIDs)
}

func (s *cacheBackedRoleStore) GetEntityRoleIDs(
	ctx context.Context, entityID string, groupIDs []string, ouID string,
) ([]string, error) {
	return s.store.GetEntityRoleIDs(ctx, entityID, groupIDs, ouID)
}

func (s *cacheBackedRoleStore) IsRoleDeclarative(ctx context.Context, roleID string) (bool, error) {
	return s.store.IsRoleDeclarative(ctx, roleID)
}

func (s *cacheBackedRoleStore) GetReferencedPermissions(ctx context.Context) ([]ResourcePermissions, error) {
	return s.store.GetReferencedPermissions(ctx)
}

// DeleteRolePermission strips a permission from every role holding it, so it cannot point-invalidate
// the way the single-role writes above do: the affected role ids are not known here. A cached
// RoleWithPermissions carries its permission list, so leaving the cache alone would keep serving the
// deleted permission. Clearing is the correct trade — this runs only when a resource server,
// resource or action is deleted, which is rare, while a stale permission is an authorization defect.
func (s *cacheBackedRoleStore) DeleteRolePermission(
	ctx context.Context, resourceServerID, permission string) (int64, error) {
	deleted, err := s.store.DeleteRolePermission(ctx, resourceServerID, permission)
	if err != nil {
		return deleted, err
	}
	if deleted > 0 {
		if clearErr := s.roleByIDCache.Clear(ctx); clearErr != nil {
			s.logger.Error(ctx, "Failed to clear role cache after permission deletion",
				log.String("resourceServerID", resourceServerID), log.String("permission", permission),
				log.Error(clearErr))
		}
	}
	return deleted, nil
}

func (s *cacheBackedRoleStore) GetAllPermissionsForAssignees(
	ctx context.Context, entityID string, groupIDs []string,
) ([]ResourcePermissions, error) {
	return s.store.GetAllPermissionsForAssignees(ctx, entityID, groupIDs)
}
