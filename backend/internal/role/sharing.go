// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"context"
	"errors"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"

	"github.com/thunder-id/thunderid/internal/sharing"
	"github.com/thunder-id/thunderid/internal/system/log"
)

// RoleSharingType is the sharing framework's identifier for roles.
const RoleSharingType sharing.ResourceType = resourceTypeRole

// The fields a role sharing policy governs. A role's definition stays with its owner, so the only
// thing a reached organization unit holds for itself is who the role is assigned to there. The
// coarse field covers every kind of assignee, and each finer one falls back to it.
const (
	sharingFieldAssignments = "assignments"
	sharingFieldUsers       = sharingFieldAssignments + ".users"
	sharingFieldApps        = sharingFieldAssignments + ".apps"
	sharingFieldAgents      = sharingFieldAssignments + ".agents"
	sharingFieldGroups      = sharingFieldAssignments + ".groups"
)

// sharingFieldByAssigneeType maps each kind of assignee to the field a policy governs it through.
var sharingFieldByAssigneeType = map[AssigneeType]string{
	AssigneeTypeUser:  sharingFieldUsers,
	AssigneeTypeApp:   sharingFieldApps,
	AssigneeTypeAgent: sharingFieldAgents,
	AssigneeTypeGroup: sharingFieldGroups,
}

// roleSharingDeclaration is how a role participates in sharing: the framework asks it what roles
// are called, which fields a policy may govern, and who owns one.
//
// Sharing a role makes it assignable in the reached organization units. It does not make the
// role's name or permissions editable there.
type roleSharingDeclaration struct {
	roleStore roleStoreInterface
	logger    *log.Logger
}

// newRoleSharingDeclaration returns the declaration registered with the sharing framework.
func newRoleSharingDeclaration(roleStore roleStoreInterface) *roleSharingDeclaration {
	return &roleSharingDeclaration{
		roleStore: roleStore,
		logger:    log.GetLogger().With(log.String(log.LoggerKeyComponentName, "RoleSharingDeclaration")),
	}
}

// ResourceType identifies roles to the sharing framework.
func (d *roleSharingDeclaration) ResourceType() sharing.ResourceType {
	return RoleSharingType
}

// Fields declares who may hold the role in a reached organization unit, per kind of assignee.
//
// Every field defaults to editable, so a policy that names no rule lets the reached unit assign
// the role to anyone it has. A policy narrows that by locking a kind. Each finer field carries the
// default itself as well, because the framework answers a field no rule names from its own default.
func (d *roleSharingDeclaration) Fields() []sharing.FieldDeclaration {
	finer := []string{sharingFieldUsers, sharingFieldApps, sharingFieldAgents, sharingFieldGroups}
	fields := make([]sharing.FieldDeclaration, 0, len(finer)+1)
	fields = append(fields, sharing.FieldDeclaration{
		Key:     sharingFieldAssignments,
		Kind:    sharing.FieldReferenceSet,
		Default: &sharing.OverlayRule{Editable: true},
	})
	for _, key := range finer {
		fields = append(fields, sharing.FieldDeclaration{
			Key:         key,
			FallbackKey: sharingFieldAssignments,
			Kind:        sharing.FieldReferenceSet,
			Default:     &sharing.OverlayRule{Editable: true},
		})
	}
	return fields
}

// OwningOUID returns the organization unit that owns a role.
func (d *roleSharingDeclaration) OwningOUID(
	ctx context.Context, resourceID string,
) (string, *tidcommon.ServiceError) {
	role, err := d.roleStore.GetRole(ctx, resourceID)
	if err != nil {
		if errors.Is(err, ErrRoleNotFound) {
			return "", &ErrorRoleNotFound
		}
		d.logger.Error(ctx, "Failed to resolve the organization unit that owns a role",
			log.String("id", resourceID), log.Error(err))
		return "", &tidcommon.InternalServerError
	}
	return role.OUID, nil
}

// ValidateMembers refuses a rule that lists values. A rule on a role says only whether a kind of
// assignee may hold the role in the reached organization units. Which assignees hold it is for
// each of those units to decide, so there is no value for the sharing unit to pin, offer or exclude.
func (d *roleSharingDeclaration) ValidateMembers(
	_ context.Context, _, _, _ string, _ []string,
) *tidcommon.ServiceError {
	return &ErrorSharingRuleValuesNotSupported
}

// DeleteOverlayValues removes the assignments of a role made in an organization unit that has just
// lost the role. A role keeps an organization unit's own state as assignments rather than in the
// framework's overlay table, so the framework calls this in place of clearing its own.
func (d *roleSharingDeclaration) DeleteOverlayValues(ctx context.Context, resourceID, ouID string) error {
	return d.roleStore.DeleteAssignmentsByRoleAndOU(ctx, resourceID, ouID)
}

// requireAssignable refuses assignments the role's sharing does not allow: one made in an
// organization unit the role is neither owned by nor shared with, and one of a type of assignee the
// sharing terms lock there. The assignments carry their public types and the organization unit each
// is made in.
func requireAssignable(
	ctx context.Context,
	sharingSvc sharing.SharingServiceInterface,
	roleID string,
	assignments []RoleAssignment,
	loggerComponent string,
) *tidcommon.ServiceError {
	var ouIDs []string
	fieldsByOU := make(map[string][]string)
	for _, a := range assignments {
		if _, seen := fieldsByOU[a.OUID]; !seen {
			ouIDs = append(ouIDs, a.OUID)
		}
		fieldsByOU[a.OUID] = append(fieldsByOU[a.OUID], sharingFieldByAssigneeType[a.Type])
	}

	for _, ouID := range ouIDs {
		overlay, svcErr := sharingSvc.ResolveOverlayRules(ctx, RoleSharingType, roleID, ouID)
		if svcErr != nil {
			log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponent)).Error(ctx,
				"Failed to resolve how a role is shared with an organization unit",
				log.String("id", roleID), log.String("ouID", ouID), log.String("code", svcErr.Code))
			return &tidcommon.InternalServerError
		}
		if overlay.Owned {
			continue
		}
		if !overlay.Visible {
			return &ErrorRoleNotAssignableInOrganizationUnit
		}
		for _, field := range fieldsByOU[ouID] {
			if rule, ok := overlay.Rules[field]; !ok || !rule.Editable {
				return &ErrorAssigneeTypeNotAssignable
			}
		}
	}
	return nil
}
