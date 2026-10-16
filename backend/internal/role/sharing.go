// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"context"
	"errors"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"

	"github.com/thunder-id/thunderid/internal/entity"
	"github.com/thunder-id/thunderid/internal/group"
	oupkg "github.com/thunder-id/thunderid/internal/ou"
	"github.com/thunder-id/thunderid/internal/sharing"
	"github.com/thunder-id/thunderid/internal/system/log"
	"github.com/thunder-id/thunderid/internal/system/utils"
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

// roleAssignmentScope decides which organization unit an assignment is made in, and whether the role
// may be assigned there.
type roleAssignmentScope struct {
	sharingService sharing.SharingServiceInterface
	entityService  entity.EntityServiceInterface
	groupService   group.GroupServiceInterface
	// entitySharingTypes names the sharing resource type of each kind of entity that can itself be
	// shared, so an assignment may be made in an organization unit the assignee is shared with.
	entitySharingTypes map[providers.EntityCategory]sharing.ResourceType
	logger             *log.Logger
}

// newRoleAssignmentScope creates a new instance of roleAssignmentScope.
func newRoleAssignmentScope(
	sharingService sharing.SharingServiceInterface,
	entityService entity.EntityServiceInterface,
	groupService group.GroupServiceInterface,
	entitySharingTypes map[providers.EntityCategory]sharing.ResourceType,
) *roleAssignmentScope {
	return &roleAssignmentScope{
		sharingService:     sharingService,
		entityService:      entityService,
		groupService:       groupService,
		entitySharingTypes: entitySharingTypes,
		logger:             log.GetLogger().With(log.String(log.LoggerKeyComponentName, "RoleAssignmentScope")),
	}
}

// resolve checks that every assignee exists under the type it was given as, and returns the
// assignments with the organization unit each is made in filled in. One that names none is made in
// the assignee's own organization unit.
//
// With requireMembership, an assignment naming another organization unit is refused unless the
// assignee is shared with it. Removing an assignment does not ask for that, so an assignment can
// still be cleaned up after the assignee stopped being shared there.
func (s *roleAssignmentScope) resolve(
	ctx context.Context, assignments []RoleAssignment, requireMembership bool,
) ([]RoleAssignment, *tidcommon.ServiceError) {
	ownOUs, svcErr := s.assigneeOUs(ctx, assignments)
	if svcErr != nil {
		return nil, svcErr
	}

	resolved := make([]RoleAssignment, len(assignments))
	for i, a := range assignments {
		resolved[i] = a
		ownOU := ownOUs[assigneeKey(a)]
		if a.OUID == "" {
			resolved[i].OUID = ownOU
			continue
		}
		if a.OUID == ownOU || !requireMembership {
			continue
		}
		shared, svcErr := s.isSharedWith(ctx, a, a.OUID)
		if svcErr != nil {
			return nil, svcErr
		}
		if !shared {
			return nil, &ErrorAssigneeNotInOrganizationUnit
		}
	}
	return resolved, nil
}

// assigneeOUs returns the organization unit each assignee belongs to, keyed by assigneeKey. An
// assignee that does not exist, or exists under another type, is refused.
func (s *roleAssignmentScope) assigneeOUs(
	ctx context.Context, assignments []RoleAssignment,
) (map[string]string, *tidcommon.ServiceError) {
	typeByID := make(map[string]AssigneeType)
	var groupIDs []string
	for _, a := range assignments {
		if a.Type.IsEntityType() {
			if existing, ok := typeByID[a.ID]; ok && existing != a.Type {
				return nil, &ErrorInvalidAssignmentID
			}
			typeByID[a.ID] = a.Type
		} else if a.Type == AssigneeTypeGroup {
			groupIDs = append(groupIDs, a.ID)
		}
	}
	groupIDs = utils.UniqueStrings(groupIDs)

	ownOUs := make(map[string]string, len(assignments))
	if len(typeByID) > 0 {
		entityIDs := make([]string, 0, len(typeByID))
		for id := range typeByID {
			entityIDs = append(entityIDs, id)
		}
		entities, err := s.entityService.GetEntitiesByIDs(ctx, entityIDs)
		if err != nil {
			s.logger.Error(ctx, "Failed to fetch entities for assignment validation", log.Error(err))
			return nil, &tidcommon.InternalServerError
		}
		if len(entities) != len(entityIDs) {
			return nil, &ErrorInvalidAssignmentID
		}
		for _, e := range entities {
			claimed := typeByID[e.ID]
			if actual := AssigneeType(e.Category); claimed != actual {
				s.logger.Debug(ctx, "Assignment type mismatch", log.String("id", e.ID),
					log.String("claimed", string(claimed)), log.String("actual", string(actual)))
				return nil, &ErrorInvalidAssignmentID
			}
			ownOUs[assigneeKey(RoleAssignment{ID: e.ID, Type: claimed})] = e.OUID
		}
	}

	if len(groupIDs) > 0 {
		// The group service logs its own failure, so it is passed on without a second entry.
		groups, svcErr := s.groupService.GetGroupsByIDs(ctx, groupIDs)
		if svcErr != nil {
			return nil, &tidcommon.InternalServerError
		}
		for _, id := range groupIDs {
			g, ok := groups[id]
			if !ok {
				s.logger.Debug(ctx, "Invalid group assignee found", log.String("id", id))
				return nil, &ErrorInvalidAssignmentID
			}
			ownOUs[assigneeKey(RoleAssignment{ID: id, Type: AssigneeTypeGroup})] = g.OUID
		}
	}
	return ownOUs, nil
}

// isSharedWith reports whether an assignee is shared with an organization unit other than its own.
// Only a kind of entity that is itself a shared resource type can be.
func (s *roleAssignmentScope) isSharedWith(
	ctx context.Context, assignment RoleAssignment, ouID string,
) (bool, *tidcommon.ServiceError) {
	sharingType, ok := s.entitySharingTypes[providers.EntityCategory(assignment.Type)]
	if !ok {
		return false, nil
	}
	shared, svcErr := s.sharingService.IsVisible(ctx, sharingType, assignment.ID, ouID)
	// An id naming no organization unit is answered as one the assignee is not shared with, so the
	// caller's mistake is not reported as a server failure and does not tell the two apart.
	if svcErr != nil && svcErr.Code == oupkg.ErrorOrganizationUnitNotFound.Code {
		return false, nil
	}
	if svcErr != nil {
		s.logger.Error(ctx, "Failed to resolve whether an assignee is shared with an organization unit",
			log.String("id", assignment.ID), log.String("ouID", ouID), log.String("code", svcErr.Code))
		return false, &tidcommon.InternalServerError
	}
	return shared, nil
}

// requireAssignable refuses assignments the role's sharing does not allow: one made in an
// organization unit the role is neither owned by nor shared with, and one of a kind the sharing
// terms lock there. The assignments carry their public types and the organization unit each is
// made in.
func (s *roleAssignmentScope) requireAssignable(
	ctx context.Context, roleID string, assignments []RoleAssignment,
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
		overlay, svcErr := s.sharingService.ResolveOverlayRules(ctx, RoleSharingType, roleID, ouID)
		if svcErr != nil {
			s.logger.Error(ctx, "Failed to resolve how a role is shared with an organization unit",
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

// assigneeKey identifies an assignee across entities and groups, whose ids are separate spaces.
func assigneeKey(assignment RoleAssignment) string {
	if assignment.Type == AssigneeTypeGroup {
		return string(AssigneeTypeGroup) + ":" + assignment.ID
	}
	return string(assigneeTypeEntity) + ":" + assignment.ID
}
