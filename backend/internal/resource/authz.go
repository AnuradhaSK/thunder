// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"context"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"

	"github.com/thunder-id/thunderid/internal/sharing"
	"github.com/thunder-id/thunderid/internal/system/security"
)

// requireOwnOUScope rejects the call unless the caller holds the root system permission, is an
// internal runtime caller (bootstrap, flow executors), or the caller's own token-issued
// organization unit equals targetOUID. Mirrors internal/role's identical primitive
// (internal/role/authz.go): neither system:resource-servers nor system:resource-servers:view
// carries a subtree tier, so a caller holding either (without the root permission) is confined to
// its own OU on every action the scope otherwise permits. This governs create and read/list paths;
// update/delete of an already-existing resource server/resource/action is separately governed by
// sharing.RequireOwnership(ForDeletion), which applies the identical "root bypasses, else must
// match" rule against the resource's owning OU (its resource server's OUID, for a resource/action)
// rather than an arbitrary target OU.
func requireOwnOUScope(ctx context.Context, targetOUID string) *tidcommon.ServiceError {
	if security.IsRuntimeContext(ctx) || security.HasSystemPermission(security.GetPermissions(ctx)) {
		return nil
	}
	if security.GetOUID(ctx) != targetOUID {
		return &ErrorResourceOutsideOwnOUScope
	}
	return nil
}

// RequireVisibility enforces that the caller can at least see a resource server/resource/action it
// did not create: either its own OU owns owningOUID outright (requireOwnOUScope), or it currently
// has share visibility of resourceID (sharing.IsShared). Mirrors internal/role's
// GetRoleWithPermissions read-path pattern. Used to gate single-resource reads and every
// share-grant operation (share/list-grants/unshare), the same way Role's own share-grant handlers
// first resolve the role (which applies this identical check) before acting on it.
func (rs *resourceService) RequireVisibility(
	ctx context.Context, resourceType sharing.ResourceType, resourceID, owningOUID string,
) *tidcommon.ServiceError {
	svcErr := requireOwnOUScope(ctx, owningOUID)
	if svcErr == nil {
		return nil
	}
	shared, sharedErr := rs.sharingService.IsShared(ctx, resourceType, resourceID, security.GetOUID(ctx))
	if sharedErr != nil {
		return sharedErr
	}
	if !shared {
		return svcErr
	}
	return nil
}
