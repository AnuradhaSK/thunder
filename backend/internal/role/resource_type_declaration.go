// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"context"

	"github.com/thunder-id/thunderid/internal/sharing"
	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
)

// roleSharingResourceType is role's identifier within the generic sharing framework.
const roleSharingResourceType sharing.ResourceType = "role"

// Templated field keys. Editability of a role's assignments is independently controllable per
// assignee type (a sharee OU might be allowed to assign its own groups but not its own users, for
// example): each per-type key falls back to the blanket roleTemplatedFieldAssignments key when
// left unset, so an owner can set one policy that covers every type at once, or override a single
// type individually. Core fields (name, permissions) are never registered with the sharing
// framework — they are always resolved from the owning OU by roleService itself.
const (
	roleTemplatedFieldAssignments      = "assignments"
	roleTemplatedFieldAssignmentsUser  = "assignments.user"
	roleTemplatedFieldAssignmentsGroup = "assignments.group"
	roleTemplatedFieldAssignmentsApp   = "assignments.app"
	roleTemplatedFieldAssignmentsAgent = "assignments.agent"
)

// assignmentsFieldKeyForType returns the templated field key governing editability of
// assignments of assignee type t, or "" if t is not a recognized public assignee type.
func assignmentsFieldKeyForType(t AssigneeType) string {
	switch t {
	case AssigneeTypeUser:
		return roleTemplatedFieldAssignmentsUser
	case AssigneeTypeGroup:
		return roleTemplatedFieldAssignmentsGroup
	case AssigneeTypeApp:
		return roleTemplatedFieldAssignmentsApp
	case AssigneeTypeAgent:
		return roleTemplatedFieldAssignmentsAgent
	default:
		return ""
	}
}

// roleResourceTypeDeclaration implements sharing.ResourceTypeDeclaration and sharing.SharingHooks
// for role, onboarding it onto the generic sharing/templated-config framework.
type roleResourceTypeDeclaration struct {
	store roleStoreInterface
}

// newRoleResourceTypeDeclaration creates role's sharing.ResourceTypeDeclaration.
func newRoleResourceTypeDeclaration(store roleStoreInterface) sharing.ResourceTypeDeclaration {
	return &roleResourceTypeDeclaration{store: store}
}

// ResourceType implements sharing.ResourceTypeDeclaration.
func (d *roleResourceTypeDeclaration) ResourceType() sharing.ResourceType {
	return roleSharingResourceType
}

// TemplatedFields implements sharing.ResourceTypeDeclaration. Whether a sharee OU may edit its own
// assignments of a given assignee type is controlled per grant (see sharing.SharePolicy's
// EditableFields), not declared here; a new sharee starts with an empty assignment set regardless
// (see roleService's resolution of assignments for a shared role) — never inheriting the owner's
// own assignees.
//
// The four per-type fields each declare roleTemplatedFieldAssignments as their FallbackKey: a
// grant that names that one blanket field makes every assignee type editable at once, without
// needing to name each type individually, while a grant wanting finer control can still name a
// single type's own specific field.
func (d *roleResourceTypeDeclaration) TemplatedFields() []sharing.TemplatedFieldDeclaration {
	return []sharing.TemplatedFieldDeclaration{
		{Key: roleTemplatedFieldAssignments},
		{Key: roleTemplatedFieldAssignmentsUser, FallbackKey: roleTemplatedFieldAssignments},
		{Key: roleTemplatedFieldAssignmentsGroup, FallbackKey: roleTemplatedFieldAssignments},
		{Key: roleTemplatedFieldAssignmentsApp, FallbackKey: roleTemplatedFieldAssignments},
		{Key: roleTemplatedFieldAssignmentsAgent, FallbackKey: roleTemplatedFieldAssignments},
	}
}

// OnUnshare implements sharing.SharingHooks: when ouID loses access to a role (its share/reshare
// grant is revoked), its own assignments for that role are deleted so it does not retain a stale,
// permanent permission grant.
func (d *roleResourceTypeDeclaration) OnUnshare(ctx context.Context, resourceID, ouID string) error {
	return d.store.DeleteAssignmentsByOUID(ctx, resourceID, ouID)
}

// ErrorResourceDeletionRestrictedToOwner implements sharing.DeletionOwnershipError: a role-specific
// error, distinct from the generic sharing.ErrorCoreConfigOwnerOnly, returned when a non-owning
// organization unit (including one the role has been shared or reshared to) attempts to delete it.
func (d *roleResourceTypeDeclaration) ErrorResourceDeletionRestrictedToOwner() *tidcommon.ServiceError {
	return &ErrorRoleDeletionRestrictedToOwner
}
