// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"context"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"

	"github.com/thunder-id/thunderid/internal/system/security"
)

// requireOwnOUScope rejects the call unless the caller holds the root system permission, is an
// internal runtime caller (bootstrap, flow executors), or the caller's own token-issued
// organization unit equals targetOUID. Neither the system:roles nor system:roles:view scope
// carries a subtree tier: a caller holding either (without the root permission) is confined to its
// own OU on every action the scope otherwise permits. This governs read/list/assignment paths;
// core-config writes (create/update/delete) are separately governed by sharing.RequireOwnership,
// which applies the identical "root bypasses, else must match" rule against the resource's owning
// OU rather than an arbitrary target OU.
func requireOwnOUScope(ctx context.Context, targetOUID string) *tidcommon.ServiceError {
	if security.IsRuntimeContext(ctx) || security.HasSystemPermission(security.GetPermissions(ctx)) {
		return nil
	}
	if security.GetOUID(ctx) != targetOUID {
		return &ErrorRoleOutsideOwnOUScope
	}
	return nil
}
