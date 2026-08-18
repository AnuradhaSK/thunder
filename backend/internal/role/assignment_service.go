// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"

	"github.com/thunder-id/thunderid/internal/entity"
	"github.com/thunder-id/thunderid/internal/entitytype"
	"github.com/thunder-id/thunderid/internal/group"
	"github.com/thunder-id/thunderid/internal/sharing"
	"github.com/thunder-id/thunderid/internal/system/log"
	"github.com/thunder-id/thunderid/internal/system/resourcedependency"
	"github.com/thunder-id/thunderid/internal/system/utils"
)

const assignmentLoggerComponentName = "RoleAssignmentService"

// RoleAssignmentServiceInterface defines the interface for role assignment operations.
//
// Every method takes an explicit ouID identifying the OU the caller is acting as: empty means
// "act as the role's owning OU" (the pre-existing, still-default behavior for every caller that
// doesn't participate in sharing), a non-empty value distinct from the role's own OU means "act
// as this sharee OU". The acting OU is deliberately never inferred from the caller's own ambient
// identity/OU claim: a caller with system-wide permission routinely manages resources outside
// their own OU, and doing so is not "acting as a sharee" — it just means empty (owner) is correct
// exactly as it was before sharing existed.
type RoleAssignmentServiceInterface interface {
	GetRoleAssignments(ctx context.Context, id, ouID string, limit, offset int,
		includeDisplay bool) (*AssignmentList, *tidcommon.ServiceError)
	GetRoleAssignmentsByType(ctx context.Context, id, ouID string, limit, offset int,
		includeDisplay bool, assigneeType string) (*AssignmentList, *tidcommon.ServiceError)
	AddAssignments(ctx context.Context, id, ouID string, assignments []RoleAssignment) *tidcommon.ServiceError
	RemoveAssignments(ctx context.Context, id, ouID string, assignments []RoleAssignment) *tidcommon.ServiceError
	AddAssigneesToRoles(ctx context.Context, assignments []RoleAssignment,
		roleIDs []string) *tidcommon.ServiceError
	// GetEditableFields returns every templated field key of the role editable by the acting OU
	// (ouID, or the role's own owning OU when empty). Backs the "what can I edit" metadata endpoint.
	GetEditableFields(ctx context.Context, id, ouID string) ([]string, *tidcommon.ServiceError)
	// GetAssigningOUIDs returns every distinct OU that has made at least one assignment for the
	// role. Used by the exporter to discover per-OU assignment sets for declarative round-tripping.
	GetAssigningOUIDs(ctx context.Context, id string) ([]string, *tidcommon.ServiceError)
	// ResolveAssignmentOUIDs fills in the assigning OU of every assignment that does not already
	// declare one, using the assignee's own OU. Backs the declarative/import contract that an
	// assignment's ouId is optional and defaults to where the assignee itself lives.
	ResolveAssignmentOUIDs(
		ctx context.Context, assignments []RoleAssignment) ([]RoleAssignment, *tidcommon.ServiceError)
	GetResourceDependencies(
		ctx context.Context, resourceType, id string) ([]resourcedependency.ResourceDependency, error)
	CascadeDeleteDependencies(ctx context.Context, resourceType, id string) (int, error)
}

// roleAssignmentService is the default implementation of RoleAssignmentServiceInterface.
type roleAssignmentService struct {
	roleStore         roleStoreInterface
	entityService     entity.EntityServiceInterface
	groupService      group.GroupServiceInterface
	entityTypeService entitytype.EntityTypeServiceInterface
	sharingService    sharing.ServiceInterface
	transactioner     providers.Transactioner
}

// newRoleAssignmentService creates a new instance of roleAssignmentService.
func newRoleAssignmentService(
	roleStore roleStoreInterface,
	entityService entity.EntityServiceInterface,
	groupService group.GroupServiceInterface,
	entityTypeService entitytype.EntityTypeServiceInterface,
	sharingService sharing.ServiceInterface,
	transactioner providers.Transactioner,
) RoleAssignmentServiceInterface {
	return &roleAssignmentService{
		roleStore:         roleStore,
		entityService:     entityService,
		groupService:      groupService,
		entityTypeService: entityTypeService,
		sharingService:    sharingService,
		transactioner:     transactioner,
	}
}

// resolveActingOUID returns the OU the caller is acting as: explicitOUID if given (a sharee OU
// explicitly identified by the caller, e.g. via a request's ouId parameter), else ownerOUID.
func resolveActingOUID(explicitOUID, ownerOUID string) string {
	if explicitOUID != "" {
		return explicitOUID
	}
	return ownerOUID
}

// GetRoleAssignments retrieves assignments for a role with pagination.
func (as *roleAssignmentService) GetRoleAssignments(ctx context.Context, id, ouID string, limit, offset int,
	includeDisplay bool) (*AssignmentList, *tidcommon.ServiceError) {
	return as.GetRoleAssignmentsByType(ctx, id, ouID, limit, offset, includeDisplay, "")
}

// GetRoleAssignmentsByType retrieves assignments for a role filtered by assignee type with pagination.
func (as *roleAssignmentService) GetRoleAssignmentsByType(ctx context.Context, id, ouID string, limit, offset int,
	includeDisplay bool, assigneeType string) (*AssignmentList, *tidcommon.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, assignmentLoggerComponentName))

	if err := validatePaginationParams(limit, offset); err != nil {
		return nil, err
	}

	if id == "" {
		return nil, &ErrorMissingRoleID
	}

	role, err := as.roleStore.GetRole(ctx, id)
	if err != nil {
		if errors.Is(err, ErrRoleNotFound) {
			logger.Debug(ctx, "Role not found", log.String("id", id))
			return nil, &ErrorRoleNotFound
		}
		logger.Error(ctx, "Failed to check role existence", log.String("id", id), log.Error(err))
		return nil, &tidcommon.InternalServerError
	}
	actingOUID := resolveActingOUID(ouID, role.OUID)
	if svcErr := requireOwnOUScope(ctx, actingOUID); svcErr != nil {
		return nil, svcErr
	}

	// user/app/agent filters require fetching all entity assignments and post-filtering by category.
	if assigneeType == string(providers.EntityCategoryUser) ||
		assigneeType == string(providers.EntityCategoryApp) ||
		assigneeType == string(providers.EntityCategoryAgent) {
		return as.getAssignmentsByEntityCategory(
			ctx, id, actingOUID, limit, offset, includeDisplay, assigneeType, logger)
	}

	// For no filter or 'group' filter, use DB-level pagination directly.
	var totalCount int
	var assignments []RoleAssignment
	if assigneeType != "" {
		totalCount, err = as.roleStore.GetRoleAssignmentsCountByType(ctx, id, actingOUID, assigneeType)
	} else {
		totalCount, err = as.roleStore.GetRoleAssignmentsCount(ctx, id, actingOUID)
	}
	if err != nil {
		if errors.Is(err, errResultLimitExceededInCompositeMode) {
			return nil, &ResultLimitExceededInCompositeMode
		}
		logger.Error(ctx, "Failed to get role assignments count", log.String("id", id), log.Error(err))
		return nil, &tidcommon.InternalServerError
	}

	if assigneeType != "" {
		assignments, err = as.roleStore.GetRoleAssignmentsByType(ctx, id, actingOUID, limit, offset, assigneeType)
	} else {
		assignments, err = as.roleStore.GetRoleAssignments(ctx, id, actingOUID, limit, offset)
	}
	if err != nil {
		if errors.Is(err, errResultLimitExceededInCompositeMode) {
			return nil, &ResultLimitExceededInCompositeMode
		}
		logger.Error(ctx, "Failed to get role assignments", log.String("id", id), log.Error(err))
		return nil, &tidcommon.InternalServerError
	}

	serviceAssignments, svcErr := as.resolveAssignments(ctx, assignments, includeDisplay)
	if svcErr != nil {
		return nil, svcErr
	}

	baseURL := fmt.Sprintf("/roles/%s/assignments", id)
	extraQuery := utils.DisplayQueryParam(includeDisplay)
	if assigneeType != "" {
		extraQuery += "&type=" + assigneeType
	}
	links := utils.BuildPaginationLinks(baseURL, limit, offset, totalCount, extraQuery)

	return &AssignmentList{
		TotalResults: totalCount,
		Assignments:  serviceAssignments,
		StartIndex:   offset + 1,
		Count:        len(serviceAssignments),
		Links:        links,
	}, nil
}

// getAssignmentsByEntityCategory handles ?type=user and ?type=app filter cases.
// Since both are stored as 'entity' internally, it fetches all entity assignments,
// resolves their category, and paginates the filtered results in memory.
func (as *roleAssignmentService) getAssignmentsByEntityCategory(
	ctx context.Context, id, ouID string, limit, offset int,
	includeDisplay bool, category string, logger *log.Logger,
) (*AssignmentList, *tidcommon.ServiceError) {
	totalEntityCount, err := as.roleStore.GetRoleAssignmentsCountByType(ctx, id, ouID, string(assigneeTypeEntity))
	if err != nil {
		if errors.Is(err, errResultLimitExceededInCompositeMode) {
			return nil, &ResultLimitExceededInCompositeMode
		}
		logger.Error(ctx, "Failed to get entity assignments count", log.String("id", id), log.Error(err))
		return nil, &tidcommon.InternalServerError
	}

	var allEntityAssignments []RoleAssignment
	if totalEntityCount > 0 {
		allEntityAssignments, err = as.roleStore.GetRoleAssignmentsByType(
			ctx, id, ouID, totalEntityCount, 0, string(assigneeTypeEntity))
		if err != nil {
			if errors.Is(err, errResultLimitExceededInCompositeMode) {
				return nil, &ResultLimitExceededInCompositeMode
			}
			logger.Error(ctx, "Failed to get entity assignments", log.String("id", id), log.Error(err))
			return nil, &tidcommon.InternalServerError
		}
	}

	// Batch-resolve entity categories.
	entityCategoryMap := make(map[string]string)
	if len(allEntityAssignments) > 0 {
		entityIDs := make([]string, len(allEntityAssignments))
		for i, a := range allEntityAssignments {
			entityIDs[i] = a.ID
		}
		entities, fetchErr := as.entityService.GetEntitiesByIDs(ctx, entityIDs)
		if fetchErr != nil {
			logger.Error(ctx, "Failed to batch fetch entities for category filter", log.Error(fetchErr))
			return nil, &tidcommon.InternalServerError
		}
		for _, e := range entities {
			entityCategoryMap[e.ID] = string(e.Category)
		}
	}

	// Filter to matching category and paginate in memory.
	var filtered []RoleAssignment
	for _, a := range allEntityAssignments {
		if entityCategoryMap[a.ID] == category {
			filtered = append(filtered, a)
		}
	}

	totalCount := len(filtered)
	start := offset
	if start > totalCount {
		start = totalCount
	}
	end := start + limit
	if end > totalCount {
		end = totalCount
	}
	page := filtered[start:end]

	serviceAssignments, svcErr := as.resolveAssignments(ctx, page, includeDisplay)
	if svcErr != nil {
		return nil, svcErr
	}

	baseURL := fmt.Sprintf("/roles/%s/assignments", id)
	extraQuery := utils.DisplayQueryParam(includeDisplay) + "&type=" + category
	links := utils.BuildPaginationLinks(baseURL, limit, offset, totalCount, extraQuery)

	return &AssignmentList{
		TotalResults: totalCount,
		Assignments:  serviceAssignments,
		StartIndex:   offset + 1,
		Count:        len(serviceAssignments),
		Links:        links,
	}, nil
}

// AddAssignments adds assignments to a role.
// Assignments can be added to both mutable (DB-backed) and declarative (file-backed) roles.
func (as *roleAssignmentService) AddAssignments(
	ctx context.Context, id, ouID string, assignments []RoleAssignment) *tidcommon.ServiceError {
	return as.mutateAssignments(ctx, id, ouID, assignments, "add", as.roleStore.AddAssignments)
}

// RemoveAssignments removes assignments from a role.
// Assignments can be removed from both mutable (DB-backed) and declarative (file-backed) roles.
func (as *roleAssignmentService) RemoveAssignments(
	ctx context.Context, id, ouID string, assignments []RoleAssignment) *tidcommon.ServiceError {
	return as.mutateAssignments(ctx, id, ouID, assignments, "remove", as.roleStore.RemoveAssignments)
}

// mutateAssignments is the shared implementation behind AddAssignments/RemoveAssignments: it
// validates and resolves the acting OU via prepareAssignments (ownership for the owning OU,
// IsShared/ResolveEditability for a sharee), then applies storeFn within a transaction. Whether
// the caller may manage this role's assignments at all is decided entirely by that ownership/
// sharing determination — a sharee is deliberately never required to separately hold the role's
// own business permissions itself; that requirement would defeat the purpose of sharing a role
// to begin with, since a sharee's whole reason for needing assignment access is to extend the
// role's reach into entities it controls, not permissions it already holds.
func (as *roleAssignmentService) mutateAssignments(
	ctx context.Context, id, ouID string, assignments []RoleAssignment, verb string,
	storeFn func(ctx context.Context, id, ouID string, assignments []RoleAssignment) error,
) *tidcommon.ServiceError {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, assignmentLoggerComponentName))
	logger.Debug(ctx, "Mutating assignments for role", log.String("id", id), log.String("action", verb))

	groups, svcErr := as.prepareAssignments(ctx, id, ouID, assignments)
	if svcErr != nil {
		return svcErr
	}

	if err := as.transactioner.Transact(ctx, func(txCtx context.Context) error {
		for _, g := range groups {
			if err := storeFn(txCtx, id, g.ouID, g.assignments); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		logger.Error(ctx, "Failed to mutate assignments for role",
			log.String("id", id), log.String("action", verb), log.Error(err))
		return &tidcommon.InternalServerError
	}

	logger.Debug(ctx, "Successfully mutated assignments for role", log.String("id", id), log.String("action", verb))
	return nil
}

// AddAssigneesToRoles adds assignees to multiple roles in a single transaction.
// A single failure rolls back all role assignments.
func (as *roleAssignmentService) AddAssigneesToRoles(
	ctx context.Context,
	assignments []RoleAssignment,
	roleIDs []string,
) *tidcommon.ServiceError {
	if len(roleIDs) == 0 || len(assignments) == 0 {
		return nil
	}
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, assignmentLoggerComponentName))
	var capturedSvcErr *tidcommon.ServiceError
	err := as.transactioner.Transact(ctx, func(txCtx context.Context) error {
		for _, rid := range roleIDs {
			// Always act as the role's own owning OU: this bulk-assignment path (used during
			// registration/provisioning flows) has no sharee-OU concept of its own.
			if svcErr := as.AddAssignments(txCtx, rid, "", assignments); svcErr != nil {
				capturedSvcErr = svcErr
				return fmt.Errorf("failed to assign role %s: %s", rid, svcErr.Error.DefaultValue)
			}
		}
		return nil
	})
	if capturedSvcErr != nil {
		return capturedSvcErr
	}
	if err != nil {
		logger.Error(ctx, "Failed to add assignees to roles", log.Error(err))
		return &tidcommon.InternalServerError
	}
	return nil
}

// GetEditableFields returns every templated field key of the role editable by the acting OU
// (ouID, or the role's own owning OU when empty), enforcing the same system:roles-scope
// confinement as GetRoleAssignmentsByType's read path.
func (as *roleAssignmentService) GetEditableFields(
	ctx context.Context, id, ouID string,
) ([]string, *tidcommon.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, assignmentLoggerComponentName))

	if id == "" {
		return nil, &ErrorMissingRoleID
	}

	role, err := as.roleStore.GetRole(ctx, id)
	if err != nil {
		if errors.Is(err, ErrRoleNotFound) {
			logger.Debug(ctx, "Role not found", log.String("id", id))
			return nil, &ErrorRoleNotFound
		}
		logger.Error(ctx, "Failed to check role existence", log.String("id", id), log.Error(err))
		return nil, &tidcommon.InternalServerError
	}

	actingOUID := resolveActingOUID(ouID, role.OUID)
	if svcErr := requireOwnOUScope(ctx, actingOUID); svcErr != nil {
		return nil, svcErr
	}

	fields, svcErr := as.sharingService.ResolveEditableFields(ctx, roleSharingResourceType, id, role.OUID, actingOUID)
	if svcErr != nil {
		logger.Error(ctx, "Failed to resolve editable fields", log.String("id", id), log.Any("error", svcErr))
		return nil, &tidcommon.InternalServerError
	}
	return fields, nil
}

// GetAssigningOUIDs returns every distinct OU that has made at least one assignment for the role,
// i.e. the role's own owning OU plus any sharee OU that has used the role's assignments templated
// field. Used by the exporter to discover which per-OU assignment sets to include when exporting a
// role for declarative round-tripping; not authorization-gated since it never returns assignment
// content itself, only OU identifiers.
func (as *roleAssignmentService) GetAssigningOUIDs(ctx context.Context, id string) ([]string, *tidcommon.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, assignmentLoggerComponentName))

	ouIDs, err := as.roleStore.GetAssigningOUIDs(ctx, id)
	if err != nil {
		logger.Error(ctx, "Failed to get assigning OU IDs", log.String("id", id), log.Error(err))
		return nil, &tidcommon.InternalServerError
	}
	return ouIDs, nil
}

// assignmentGroup is one batch of assignments sharing a single assigning OU. Assignments carrying
// an explicit RoleAssignment.OUID (the declarative/import path) form their own group; the rest fall
// into the group for the OU the caller is acting as.
type assignmentGroup struct {
	ouID        string
	assignments []RoleAssignment
}

// groupAssignmentsByOU buckets assignments by their effective assigning OU — the assignment's own
// OUID when set, otherwise defaultOUID — preserving first-seen OU order so the resulting writes and
// error reporting are deterministic.
func groupAssignmentsByOU(assignments []RoleAssignment, defaultOUID string) []assignmentGroup {
	indexByOU := make(map[string]int, len(assignments))
	groups := make([]assignmentGroup, 0, 1)
	for _, a := range assignments {
		ouID := a.OUID
		if ouID == "" {
			ouID = defaultOUID
		}
		idx, ok := indexByOU[ouID]
		if !ok {
			idx = len(groups)
			indexByOU[ouID] = idx
			groups = append(groups, assignmentGroup{ouID: ouID})
		}
		groups[idx].assignments = append(groups[idx].assignments, a)
	}
	return groups
}

// prepareAssignments validates and normalizes assignments before a mutation.
// Unlike the previous role service implementation, this allows modifying assignments for
// both mutable and declarative (file-backed) roles.
//
// prepareAssignments validates the request, buckets the assignments by the OU each is recorded
// under (the role's own OU, or a sharee OU's ID), and verifies every one of those OUs is allowed to
// write assignments: the owning OU always may; any other OU must currently have a valid
// share/reshare grant for the role, with assignments of every type present in that OU's bucket
// editable for it (editability is controlled independently per assignee type — see
// roleResourceTypeDeclaration). Without this check, any OU could write itself permissions via
// ROLE_ASSIGNMENT with no sharing relationship at all.
func (as *roleAssignmentService) prepareAssignments(
	ctx context.Context, id, ouID string, assignments []RoleAssignment,
) ([]assignmentGroup, *tidcommon.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, assignmentLoggerComponentName))

	if id == "" {
		return nil, &ErrorMissingRoleID
	}

	if err := as.validateAssignmentsRequest(assignments); err != nil {
		return nil, err
	}

	role, err := as.roleStore.GetRole(ctx, id)
	if err != nil {
		if errors.Is(err, ErrRoleNotFound) {
			logger.Debug(ctx, "Role not found", log.String("id", id))
			return nil, &ErrorRoleNotFound
		}
		logger.Error(ctx, "Failed to check role existence", log.String("id", id), log.Error(err))
		return nil, &tidcommon.InternalServerError
	}

	groups := groupAssignmentsByOU(assignments, resolveActingOUID(ouID, role.OUID))

	for _, g := range groups {
		// Additive to, not a replacement for, the sharing-editability checks below: the caller must
		// both be entitled to act as this OU at all (this check) and, when acting as a sharee, have
		// a valid grant with the field made editable (the checks that follow).
		if svcErr := requireOwnOUScope(ctx, g.ouID); svcErr != nil {
			return nil, svcErr
		}

		if g.ouID == role.OUID {
			continue
		}

		shared, svcErr := as.sharingService.IsShared(ctx, roleSharingResourceType, id, g.ouID)
		if svcErr != nil {
			logger.Error(ctx, "Failed to check role sharing", log.String("id", id), log.Any("error", svcErr))
			return nil, &tidcommon.InternalServerError
		}
		if !shared {
			logger.Debug(ctx, "Role is not shared to the acting OU",
				log.String("id", id), log.String("ouID", g.ouID))
			return nil, &ErrorRoleNotSharedToOU
		}
		for _, assigneeType := range distinctAssigneeTypes(g.assignments) {
			fieldKey := assignmentsFieldKeyForType(assigneeType)
			editable, svcErr := as.sharingService.ResolveEditability(
				ctx, roleSharingResourceType, id, role.OUID, g.ouID, fieldKey)
			if svcErr != nil {
				logger.Error(ctx, "Failed to resolve assignment editability",
					log.String("id", id), log.Any("error", svcErr))
				return nil, &tidcommon.InternalServerError
			}
			if !editable {
				logger.Debug(ctx, "Assignments are not editable for the acting OU",
					log.String("id", id), log.String("ouID", g.ouID),
					log.String("assigneeType", string(assigneeType)))
				return nil, &ErrorAssignmentsNotEditable
			}
		}
	}

	if err := as.validateAssignmentIDs(ctx, assignments); err != nil {
		return nil, err
	}

	for i := range groups {
		groups[i].assignments = normalizeAssignments(groups[i].assignments)
	}

	return groups, nil
}

// validateAssignmentsRequest validates the assignments request.
// Accepts public types 'user', 'app', 'agent', 'group'.
func (as *roleAssignmentService) validateAssignmentsRequest(
	assignments []RoleAssignment) *tidcommon.ServiceError {
	if len(assignments) == 0 {
		return &ErrorEmptyAssignments
	}

	for _, assignment := range assignments {
		if !assignment.Type.IsEntityType() && assignment.Type != AssigneeTypeGroup {
			return &ErrorInvalidAssigneeType
		}
		if assignment.ID == "" {
			return &ErrorInvalidRequestFormat
		}
	}

	return nil
}

// validateAssignmentIDs validates assignment IDs before normalization.
func (as *roleAssignmentService) validateAssignmentIDs(
	ctx context.Context, assignments []RoleAssignment) *tidcommon.ServiceError {
	return validateAssignmentIDs(ctx, assignments, as.entityService, as.groupService, assignmentLoggerComponentName)
}

// ResolveAssignmentOUIDs returns assignments with every blank OUID replaced by the assignee's own
// OU. Assignments that already declare an OUID are returned untouched, and an assignee that cannot
// be found is left blank rather than rejected here: existence is validated by the write path
// (validateAssignmentIDs), which reports it as an invalid assignment ID.
func (as *roleAssignmentService) ResolveAssignmentOUIDs(
	ctx context.Context, assignments []RoleAssignment,
) ([]RoleAssignment, *tidcommon.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, assignmentLoggerComponentName))

	var entityIDs, groupIDs []string
	for _, a := range assignments {
		if a.OUID != "" {
			continue
		}
		if a.Type.IsEntityType() {
			entityIDs = append(entityIDs, a.ID)
		} else if a.Type == AssigneeTypeGroup {
			groupIDs = append(groupIDs, a.ID)
		}
	}
	if len(entityIDs) == 0 && len(groupIDs) == 0 {
		return assignments, nil
	}

	ouByEntityID := make(map[string]string, len(entityIDs))
	if len(entityIDs) > 0 {
		entities, err := as.entityService.GetEntitiesByIDs(ctx, utils.UniqueStrings(entityIDs))
		if err != nil {
			logger.Error(ctx, "Failed to fetch entities to resolve assignment OUs", log.Error(err))
			return nil, &tidcommon.InternalServerError
		}
		for _, e := range entities {
			ouByEntityID[e.ID] = e.OUID
		}
	}

	ouByGroupID := make(map[string]string, len(groupIDs))
	if len(groupIDs) > 0 {
		groups, svcErr := as.groupService.GetGroupsByIDs(ctx, utils.UniqueStrings(groupIDs))
		if svcErr != nil {
			logger.Error(ctx, "Failed to fetch groups to resolve assignment OUs",
				log.String("error", svcErr.Error.DefaultValue))
			return nil, &tidcommon.InternalServerError
		}
		for id, g := range groups {
			ouByGroupID[id] = g.OUID
		}
	}

	resolved := make([]RoleAssignment, len(assignments))
	for i, a := range assignments {
		resolved[i] = a
		if a.OUID != "" {
			continue
		}
		if a.Type.IsEntityType() {
			resolved[i].OUID = ouByEntityID[a.ID]
		} else if a.Type == AssigneeTypeGroup {
			resolved[i].OUID = ouByGroupID[a.ID]
		}
	}

	return resolved, nil
}

// validateAssignmentIDs validates assignment IDs checking entity/group existence and type matching.
func validateAssignmentIDs(
	ctx context.Context,
	assignments []RoleAssignment,
	entitySvc entity.EntityServiceInterface,
	groupSvc group.GroupServiceInterface,
	loggerComponent string,
) *tidcommon.ServiceError {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponent))

	typeByID := make(map[string]AssigneeType)
	var groupIDs []string

	for _, a := range assignments {
		if a.Type.IsEntityType() {
			if existing, ok := typeByID[a.ID]; ok && existing != a.Type {
				return &ErrorInvalidAssignmentID
			}
			typeByID[a.ID] = a.Type
		} else if a.Type == AssigneeTypeGroup {
			groupIDs = append(groupIDs, a.ID)
		}
	}

	groupIDs = utils.UniqueStrings(groupIDs)

	if len(typeByID) > 0 {
		entityIDs := make([]string, 0, len(typeByID))
		for id := range typeByID {
			entityIDs = append(entityIDs, id)
		}

		entities, err := entitySvc.GetEntitiesByIDs(ctx, entityIDs)
		if err != nil {
			logger.Error(ctx, "Failed to fetch entities for assignment validation", log.Error(err))
			return &tidcommon.InternalServerError
		}

		if len(entities) != len(entityIDs) {
			return &ErrorInvalidAssignmentID
		}

		for _, e := range entities {
			claimed := typeByID[e.ID]
			actual := AssigneeType(e.Category)
			if claimed != actual {
				logger.Debug(ctx, "Assignment type mismatch", log.String("id", e.ID),
					log.String("claimed", string(claimed)), log.String("actual", string(actual)))
				return &ErrorInvalidAssignmentID
			}
		}
	}

	if len(groupIDs) > 0 {
		if err := groupSvc.ValidateGroupIDs(ctx, groupIDs); err != nil {
			if err.Code == group.ErrorInvalidGroupMemberID.Code {
				logger.Debug(ctx, "Invalid group member IDs found")
				return &ErrorInvalidAssignmentID
			}
			logger.Error(ctx, "Failed to validate group IDs", log.String("error", err.Error.DefaultValue))
			return &tidcommon.InternalServerError
		}
	}

	return nil
}

// resolveAssignments resolves the public types and optionally display names for role assignments.
func (as *roleAssignmentService) resolveAssignments(
	ctx context.Context,
	assignments []RoleAssignment,
	includeDisplay bool,
) ([]RoleAssignmentWithDisplay, *tidcommon.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, assignmentLoggerComponentName))

	var entityIDs, groupIDs []string
	for _, a := range assignments {
		switch a.Type {
		case assigneeTypeEntity:
			entityIDs = append(entityIDs, a.ID)
		case AssigneeTypeGroup:
			groupIDs = append(groupIDs, a.ID)
		}
	}

	// Always batch-fetch entities to resolve their category (user vs app) for the API response type.
	var entityMap map[string]*providers.Entity
	if len(entityIDs) > 0 {
		entities, err := as.entityService.GetEntitiesByIDs(ctx, entityIDs)
		if err != nil {
			logger.Error(ctx, "Failed to batch fetch entities for assignments", log.Error(err))
			return nil, &tidcommon.InternalServerError
		}
		entityMap = make(map[string]*providers.Entity, len(entities))
		for i := range entities {
			entityMap[entities[i].ID] = &entities[i]
		}
	}

	var groupsMap map[string]*group.Group
	if includeDisplay && len(groupIDs) > 0 {
		var svcErr *tidcommon.ServiceError
		groupsMap, svcErr = as.groupService.GetGroupsByIDs(ctx, groupIDs)
		if svcErr != nil {
			logger.Warn(ctx, "Failed to batch fetch groups for display names", log.Any("error", svcErr))
		}
	}

	// Resolve display attribute paths for user-category entities.
	var displayAttrPaths map[string]string
	if includeDisplay && entityMap != nil {
		var userTypes []string
		for _, e := range entityMap {
			if e.Category == providers.EntityCategoryUser {
				userTypes = append(userTypes, e.Type)
			}
		}
		displayAttrPaths = resolveDisplayAttributePaths(ctx, userTypes, as.entityTypeService, logger)
	}

	// Build the result slice, skipping orphaned entity assignments.
	result := make([]RoleAssignmentWithDisplay, 0, len(assignments))
	for _, a := range assignments {
		ra := RoleAssignmentWithDisplay{ID: a.ID}
		switch a.Type {
		case assigneeTypeEntity:
			e, ok := entityMap[a.ID]
			if !ok {
				logger.Warn(ctx, "Skipping orphaned entity assignment", log.String("id", a.ID))
				continue
			}
			ra.Type = AssigneeType(e.Category)
			if includeDisplay {
				if e.Category == providers.EntityCategoryUser {
					ra.Display = utils.ResolveDisplay(e.ID, e.Type, e.Attributes, displayAttrPaths)
				} else {
					ra.Display = resolveAppDisplay(*e)
				}
			}
		case AssigneeTypeGroup:
			ra.Type = AssigneeTypeGroup
			if includeDisplay {
				if groupsMap != nil {
					if g, ok := groupsMap[a.ID]; ok {
						ra.Display = g.Name
					} else {
						ra.Display = a.ID
					}
				} else {
					ra.Display = a.ID
				}
			}
		default:
			ra.Type = a.Type
			ra.Display = a.ID
		}
		result = append(result, ra)
	}
	return result, nil
}

// resolveAppDisplay extracts a display name for an app entity from its system attributes.
func resolveAppDisplay(e providers.Entity) string {
	if len(e.SystemAttributes) > 0 {
		var sysAttrs map[string]interface{}
		if err := json.Unmarshal(e.SystemAttributes, &sysAttrs); err == nil {
			if name, ok := sysAttrs["name"].(string); ok && name != "" {
				return name
			}
		}
	}
	return e.ID
}

// resolveDisplayAttributePaths collects unique user types and resolves their display
// attribute paths from the entity type service.
func resolveDisplayAttributePaths(
	ctx context.Context, userTypes []string, schemaService entitytype.EntityTypeServiceInterface,
	logger *log.Logger,
) map[string]string {
	if schemaService == nil || len(userTypes) == 0 {
		return nil
	}

	uniqueTypes := utils.UniqueNonEmptyStrings(userTypes)
	if len(uniqueTypes) == 0 {
		return nil
	}

	displayPaths, svcErr := schemaService.GetDisplayAttributesByNames(ctx, entitytype.TypeCategoryUser, uniqueTypes)
	if svcErr != nil {
		if logger != nil {
			logger.Warn(ctx, "Failed to resolve display attribute paths, skipping display resolution",
				log.Any("error", svcErr))
		}
		return nil
	}

	return displayPaths
}

// distinctAssigneeTypes returns the unique public assignee types (user/group/app/agent) present in
// assignments, in first-seen order. Called before normalizeAssignments, while public types are
// still intact.
func distinctAssigneeTypes(assignments []RoleAssignment) []AssigneeType {
	seen := make(map[AssigneeType]struct{}, len(assignments))
	types := make([]AssigneeType, 0, len(assignments))
	for _, a := range assignments {
		if _, ok := seen[a.Type]; ok {
			continue
		}
		seen[a.Type] = struct{}{}
		types = append(types, a.Type)
	}
	return types
}

// normalizeAssignments converts public 'user'/'app'/'agent' types to the internal 'entity' type.
func normalizeAssignments(assignments []RoleAssignment) []RoleAssignment {
	normalized := make([]RoleAssignment, len(assignments))
	for i, a := range assignments {
		t := a.Type
		if t.IsEntityType() {
			t = assigneeTypeEntity
		}
		normalized[i] = RoleAssignment{ID: a.ID, Type: t, OUID: a.OUID}
	}
	return normalized
}

// GetResourceDependencies implements resourcedependency.Provider. Role assignments are cleaned up
// via cascade rather than surfaced as blocking usages, so no dependencies are reported here.
func (as *roleAssignmentService) GetResourceDependencies(
	_ context.Context, _, _ string) ([]resourcedependency.ResourceDependency, error) {
	return []resourcedependency.ResourceDependency{}, nil
}

// CascadeDeleteDependencies implements resourcedependency.CascadeDeleter. It removes the role
// assignments held by the given principal when that principal is deleted. Only user, app and agent
// principals (stored as entity assignees) are handled; other resource types have no assignments.
func (as *roleAssignmentService) CascadeDeleteDependencies(
	ctx context.Context, resourceType, id string) (int, error) {
	var assigneeType AssigneeType
	switch resourceType {
	case resourcedependency.ResourceTypeUser,
		resourcedependency.ResourceTypeApplication,
		resourcedependency.ResourceTypeAgent:
		assigneeType = assigneeTypeEntity
	case resourcedependency.ResourceTypeGroup:
		assigneeType = AssigneeTypeGroup
	default:
		return 0, nil
	}

	deleted, err := as.roleStore.DeleteAssignmentsByAssignee(ctx, string(assigneeType), id)
	if err != nil {
		return 0, err
	}
	return int(deleted), nil
}
