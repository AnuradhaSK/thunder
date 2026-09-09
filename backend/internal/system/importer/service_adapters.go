// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"context"
	"encoding/json"
	"fmt"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"

	agentmodel "github.com/thunder-id/thunderid/internal/agent/model"
	layoutmgt "github.com/thunder-id/thunderid/internal/design/layout/mgt"
	thememgt "github.com/thunder-id/thunderid/internal/design/theme/mgt"
	"github.com/thunder-id/thunderid/internal/entitytype"
	"github.com/thunder-id/thunderid/internal/group"
	"github.com/thunder-id/thunderid/internal/resource"
	"github.com/thunder-id/thunderid/internal/role"
	"github.com/thunder-id/thunderid/internal/sharing"
	serverconst "github.com/thunder-id/thunderid/internal/system/constants"
	i18nmgt "github.com/thunder-id/thunderid/internal/system/i18n/mgt"
	"github.com/thunder-id/thunderid/internal/system/log"
	"github.com/thunder-id/thunderid/internal/vc/credential"
	"github.com/thunder-id/thunderid/internal/vc/presentation"
)

// resolveImportOUHandle resolves an ou_handle to its corresponding OU ID for import operations.
// If both ouID and ouHandle are provided, ouID wins and a warning is logged.
// Returns the (possibly resolved) ouID and any service error from the OU lookup.
func (s *importService) resolveImportOUHandle(
	ctx context.Context, resourceType, resourceID, resourceName, ouID, ouHandle string,
) (string, *tidcommon.ServiceError) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "ImportService"))
	if ouID != "" && ouHandle != "" {
		logger.Warn(ctx, "Both ouId and ouHandle provided; ouHandle ignored",
			log.String("resourceType", resourceType),
			log.String("resourceID", resourceID),
			log.String("resourceName", resourceName))
		return ouID, nil
	}
	if ouID == "" && ouHandle != "" {
		if s.ouService == nil {
			return "", &tidcommon.InternalServerError
		}
		resolved, svcErr := s.ouService.GetOrganizationUnitByPath(ctx, ouHandle)
		if svcErr != nil {
			return "", svcErr
		}
		return resolved.ID, nil
	}
	return ouID, nil
}

type roleDeclarativeYAML struct {
	ID          string                     `yaml:"id"`
	Name        string                     `yaml:"name"`
	Description string                     `yaml:"description,omitempty"`
	OUID        string                     `yaml:"ouId,omitempty"`
	OUHandle    string                     `yaml:"ouHandle,omitempty"`
	Permissions []role.ResourcePermissions `yaml:"permissions"`
	Assignments []role.RoleAssignment      `yaml:"assignments,omitempty"`
	Grants      []role.ShareRequest        `yaml:"grants,omitempty"`
}

// resourceServerSharingYAML captures just the sharing block of a resource_server document.
// providers.ResourceServer is the service-layer model and deliberately carries no grants
// field, so the block is decoded from the same node separately rather than widening that model.
type resourceServerSharingYAML struct {
	Grants []resource.ShareRequest `yaml:"grants,omitempty"`
}

type userDeclarativeYAML struct {
	ID          string                 `yaml:"id"`
	Type        string                 `yaml:"type"`
	OUID        string                 `yaml:"ouId,omitempty"`
	OUHandle    string                 `yaml:"ouHandle,omitempty"`
	Attributes  map[string]interface{} `yaml:"attributes"`
	Credentials map[string]interface{} `yaml:"credentials,omitempty"`
}

type entityTypeDeclarativeYAML struct {
	ID                    string                       `yaml:"id"`
	Category              entitytype.TypeCategory      `yaml:"category,omitempty"`
	Name                  string                       `yaml:"name"`
	OUID                  string                       `yaml:"ouId,omitempty"`
	OUHandle              string                       `yaml:"ouHandle,omitempty"`
	AllowSelfRegistration bool                         `yaml:"allowSelfRegistration,omitempty"`
	SystemAttributes      *entitytype.SystemAttributes `yaml:"systemAttributes,omitempty"`
	Schema                interface{}                  `yaml:"schema"`
}

type themeDeclarativeYAML struct {
	ID          string      `yaml:"id"`
	Handle      string      `yaml:"handle"`
	DisplayName string      `yaml:"displayName"`
	Description string      `yaml:"description,omitempty"`
	Theme       interface{} `yaml:"theme"`
}

type layoutDeclarativeYAML struct {
	ID          string      `yaml:"id"`
	Handle      string      `yaml:"handle"`
	DisplayName string      `yaml:"displayName"`
	Description string      `yaml:"description,omitempty"`
	Layout      interface{} `yaml:"layout"`
}

func (s *importService) importOrganizationUnit(
	ctx context.Context, doc parsedDocument, options *ImportOptions, dryRun bool,
) ImportItemOutcome {
	if s.ouService == nil {
		return unsupportedAdapterOutcome(resourceTypeOrganizationUnit, "organization unit")
	}

	var req providers.OrganizationUnit
	if err := doc.Node.Decode(&req); err != nil {
		return decodeErrorOutcome(resourceTypeOrganizationUnit, req.ID, req.Name, err)
	}

	createReq := providers.OrganizationUnitRequestWithID{
		ID:                        req.ID,
		Handle:                    req.Handle,
		Name:                      req.Name,
		Description:               req.Description,
		Parent:                    req.Parent,
		ThemeID:                   req.ThemeID,
		LayoutID:                  req.LayoutID,
		AuthFlowID:                req.AuthFlowID,
		RegistrationFlowID:        req.RegistrationFlowID,
		IsRegistrationFlowEnabled: req.IsRegistrationFlowEnabled,
		RecoveryFlowID:            req.RecoveryFlowID,
		IsRecoveryFlowEnabled:     req.IsRecoveryFlowEnabled,
		SignOutFlowID:             req.SignOutFlowID,
		LogoURL:                   req.LogoURL,
		TosURI:                    req.TosURI,
		PolicyURI:                 req.PolicyURI,
		CookiePolicyURI:           req.CookiePolicyURI,
	}
	updateReq := createReq

	if dryRun {
		if options.IsUpsertEnabled() && req.ID != "" {
			_, svcErr := s.ouService.GetOrganizationUnit(ctx, req.ID)
			if svcErr == nil {
				return successOutcome(resourceTypeOrganizationUnit, req.ID, req.Name, operationUpdate)
			}

			if !isNotFoundServiceError(svcErr) {
				return serviceErrorOutcome(resourceTypeOrganizationUnit, req.ID, req.Name, operationUpdate, svcErr)
			}
		}

		return successOutcome(resourceTypeOrganizationUnit, req.ID, req.Name, operationCreate)
	}

	if options.IsUpsertEnabled() && req.ID != "" {
		updated, svcErr := s.ouService.UpdateOrganizationUnit(ctx, req.ID, updateReq)
		if svcErr == nil {
			return successOutcome(resourceTypeOrganizationUnit, updated.ID, updated.Name, operationUpdate)
		}

		if !isNotFoundServiceError(svcErr) {
			return serviceErrorOutcome(resourceTypeOrganizationUnit, req.ID, req.Name, operationUpdate, svcErr)
		}

		created, createErr := s.ouService.CreateOrganizationUnit(ctx, createReq)
		if createErr != nil {
			return serviceErrorOutcome(resourceTypeOrganizationUnit, req.ID, req.Name, operationCreate, createErr)
		}

		return successOutcome(resourceTypeOrganizationUnit, created.ID, created.Name, operationCreate)
	}

	created, svcErr := s.ouService.CreateOrganizationUnit(ctx, createReq)
	if svcErr != nil {
		return serviceErrorOutcome(resourceTypeOrganizationUnit, req.ID, req.Name, operationCreate, svcErr)
	}

	return successOutcome(resourceTypeOrganizationUnit, created.ID, created.Name, operationCreate)
}

func (s *importService) importEntityType(
	ctx context.Context, doc parsedDocument, options *ImportOptions, dryRun bool,
) ImportItemOutcome {
	if s.entityTypeService == nil {
		return unsupportedAdapterOutcome(resourceTypeEntityType, "user type")
	}

	var req entityTypeDeclarativeYAML
	if err := doc.Node.Decode(&req); err != nil {
		return decodeErrorOutcome(resourceTypeEntityType, req.ID, req.Name, err)
	}

	var (
		schemaBytes []byte
		err         error
	)
	switch v := req.Schema.(type) {
	case string:
		schemaBytes = []byte(v)
	default:
		schemaBytes, err = json.Marshal(v)
		if err != nil {
			return ImportItemOutcome{
				ResourceType: resourceTypeEntityType,
				ResourceID:   req.ID,
				ResourceName: req.Name,
				Status:       statusFailed,
				Code:         ErrorInvalidYAMLContent.Code,
				Message:      fmt.Sprintf("failed to marshal schema: %v", err),
			}
		}
	}

	category := req.Category
	if category == "" {
		if doc.ResourceType == resourceTypeAgentType {
			category = entitytype.TypeCategoryAgent
		} else {
			category = entitytype.TypeCategoryUser
		}
	}
	if !category.IsValid() {
		return ImportItemOutcome{
			ResourceType: resourceTypeEntityType,
			ResourceID:   req.ID,
			ResourceName: req.Name,
			Status:       statusFailed,
			Code:         ErrorInvalidYAMLContent.Code,
			Message:      fmt.Sprintf("invalid entity type category %q", string(category)),
		}
	}

	createReq := entitytype.CreateEntityTypeRequestWithID{
		ID:                    req.ID,
		Name:                  req.Name,
		OUID:                  req.OUID,
		OUHandle:              req.OUHandle,
		AllowSelfRegistration: req.AllowSelfRegistration,
		SystemAttributes:      req.SystemAttributes,
		Schema:                schemaBytes,
	}
	updateReq := entitytype.UpdateEntityTypeRequest{
		Name:                  createReq.Name,
		OUID:                  createReq.OUID,
		OUHandle:              createReq.OUHandle,
		AllowSelfRegistration: createReq.AllowSelfRegistration,
		SystemAttributes:      createReq.SystemAttributes,
		Schema:                createReq.Schema,
	}

	if dryRun {
		if options.IsUpsertEnabled() && req.ID != "" {
			_, svcErr := s.entityTypeService.GetEntityType(ctx, category, req.ID, false)
			if svcErr == nil {
				return successOutcome(resourceTypeEntityType, req.ID, req.Name, operationUpdate)
			}

			if !isNotFoundServiceError(svcErr) {
				return serviceErrorOutcome(resourceTypeEntityType, req.ID, req.Name, operationUpdate, svcErr)
			}
		}

		return successOutcome(resourceTypeEntityType, req.ID, req.Name, operationCreate)
	}

	if options.IsUpsertEnabled() && req.ID != "" {
		updated, svcErr := s.entityTypeService.UpdateEntityType(ctx, category, req.ID, updateReq)
		if svcErr == nil {
			return successOutcome(resourceTypeEntityType, updated.ID, updated.Name, operationUpdate)
		}

		if !isNotFoundServiceError(svcErr) {
			return serviceErrorOutcome(resourceTypeEntityType, req.ID, req.Name, operationUpdate, svcErr)
		}

		created, createErr := s.entityTypeService.CreateEntityType(ctx, category, createReq)
		if createErr != nil {
			return serviceErrorOutcome(resourceTypeEntityType, req.ID, req.Name, operationCreate, createErr)
		}
		return successOutcome(resourceTypeEntityType, created.ID, created.Name, operationCreate)
	}

	created, svcErr := s.entityTypeService.CreateEntityType(ctx, category, createReq)
	if svcErr != nil {
		return serviceErrorOutcome(resourceTypeEntityType, req.ID, req.Name, operationCreate, svcErr)
	}
	return successOutcome(resourceTypeEntityType, created.ID, created.Name, operationCreate)
}

func (s *importService) importRole(
	ctx context.Context, doc parsedDocument, options *ImportOptions, dryRun bool,
) ImportItemOutcome {
	if s.roleService == nil {
		return unsupportedAdapterOutcome(resourceTypeRole, "role")
	}

	var req roleDeclarativeYAML
	if err := doc.Node.Decode(&req); err != nil {
		return decodeErrorOutcome(resourceTypeRole, req.ID, req.Name, err)
	}

	resolvedOUID, svcErr := s.resolveImportOUHandle(
		ctx, resourceTypeRole, req.ID, req.Name, req.OUID, req.OUHandle)
	if svcErr != nil {
		return serviceErrorOutcome(resourceTypeRole, req.ID, req.Name, operationCreate, svcErr)
	}
	req.OUID = resolvedOUID

	// Assignments are deliberately not carried inline on create: they are applied after the grants,
	// because an assignment recorded under a sharee OU is only legal once that OU's grant
	// exists. applyRoleAssignments handles both the create and the update path.
	createReq := role.RoleCreationDetail{
		ID:          req.ID,
		Name:        req.Name,
		Description: req.Description,
		OUID:        req.OUID,
		Permissions: req.Permissions,
	}
	updateReq := role.RoleUpdateDetail{
		Name:        req.Name,
		Description: req.Description,
		OUID:        req.OUID,
		Permissions: req.Permissions,
	}

	if dryRun {
		if options.IsUpsertEnabled() && req.ID != "" {
			_, svcErr := s.roleService.GetRoleWithPermissions(ctx, req.ID)
			if svcErr == nil {
				return successOutcome(resourceTypeRole, req.ID, req.Name, operationUpdate)
			}

			if !isNotFoundServiceError(svcErr) {
				return serviceErrorOutcome(resourceTypeRole, req.ID, req.Name, operationUpdate, svcErr)
			}
		}

		return successOutcome(resourceTypeRole, req.ID, req.Name, operationCreate)
	}

	if options.IsUpsertEnabled() && req.ID != "" {
		_, svcErr := s.roleService.GetRoleWithPermissions(ctx, req.ID)
		if svcErr == nil {
			updated, updateErr := s.roleService.UpdateRoleWithPermissions(ctx, req.ID, updateReq)
			if updateErr != nil {
				return serviceErrorOutcome(resourceTypeRole, req.ID, req.Name, operationUpdate, updateErr)
			}
			if svcErr := s.applyRoleSharing(ctx, updated.ID, updated.OUID, req); svcErr != nil {
				return serviceErrorOutcome(resourceTypeRole, updated.ID, updated.Name, operationUpdate, svcErr)
			}
			if svcErr := s.applyRoleAssignments(ctx, updated.ID, req.Assignments); svcErr != nil {
				return serviceErrorOutcome(resourceTypeRole, updated.ID, updated.Name, operationUpdate, svcErr)
			}
			return successOutcome(resourceTypeRole, updated.ID, updated.Name, operationUpdate)
		}

		if !isNotFoundServiceError(svcErr) {
			return serviceErrorOutcome(resourceTypeRole, req.ID, req.Name, operationUpdate, svcErr)
		}
	}

	created, svcErr := s.roleService.CreateRole(ctx, createReq)
	if svcErr != nil {
		return serviceErrorOutcome(resourceTypeRole, req.ID, req.Name, operationCreate, svcErr)
	}
	if svcErr := s.applyRoleSharing(ctx, created.ID, created.OUID, req); svcErr != nil {
		return serviceErrorOutcome(resourceTypeRole, created.ID, created.Name, operationCreate, svcErr)
	}
	if svcErr := s.applyRoleAssignments(ctx, created.ID, req.Assignments); svcErr != nil {
		return serviceErrorOutcome(resourceTypeRole, created.ID, created.Name, operationCreate, svcErr)
	}
	return successOutcome(resourceTypeRole, created.ID, created.Name, operationCreate)
}

// applyRoleSharing replays a declaratively-declared role's grants via sharingService.Share, so
// they go through the same eligibility checks a live POST /roles/{id}/grants call would, in
// declared order. A no-op when the import declares none.
func (s *importService) applyRoleSharing(
	ctx context.Context, id, ownerOUID string, req roleDeclarativeYAML,
) *tidcommon.ServiceError {
	if len(req.Grants) == 0 {
		return nil
	}
	if s.sharingService == nil {
		return tidcommon.CustomServiceError(tidcommon.InternalServerError,
			tidcommon.I18nMessage{DefaultValue: "sharingService not configured"})
	}

	for _, grant := range req.Grants {
		actingOUID := grant.InitiatingOUID
		if actingOUID == "" {
			actingOUID = ownerOUID
		}
		if _, svcErr := s.sharingService.Share(
			ctx, sharing.ResourceType(resourceTypeRole), id, ownerOUID, actingOUID, grant.ToSharePolicy(),
		); svcErr != nil {
			return svcErr
		}
	}

	return nil
}

// applyRoleAssignments writes a declaratively-declared role's assignments, whichever OU each is
// recorded under. Assignments that omit ouId have it resolved to the assignee's own OU first; the
// assignment service then buckets them by OU and authorizes each bucket independently (the owning
// OU always may; a sharee OU must hold a grant with assignments editable), so this must run
// after applyRoleSharing has replayed the grants.
func (s *importService) applyRoleAssignments(
	ctx context.Context, id string, assignments []role.RoleAssignment,
) *tidcommon.ServiceError {
	if len(assignments) == 0 {
		return nil
	}
	if s.roleAssignmentService == nil {
		return tidcommon.CustomServiceError(tidcommon.InternalServerError,
			tidcommon.I18nMessage{DefaultValue: "roleAssignmentService not configured"})
	}

	resolved, svcErr := s.roleAssignmentService.ResolveAssignmentOUIDs(ctx, assignments)
	if svcErr != nil {
		return svcErr
	}

	return s.roleAssignmentService.AddAssignments(ctx, id, "", resolved)
}

func (s *importService) importGroup(
	ctx context.Context, doc parsedDocument, options *ImportOptions, dryRun bool,
) ImportItemOutcome {
	if s.groupService == nil {
		return unsupportedAdapterOutcome(resourceTypeGroup, "group")
	}

	var req group.CreateGroupRequest
	// Use a local struct to capture the ID from YAML (ID is json:"-" on CreateGroupRequest)
	var raw struct {
		ID          string         `yaml:"id"`
		Name        string         `yaml:"name"`
		Description string         `yaml:"description,omitempty"`
		OUID        string         `yaml:"ouId,omitempty"`
		OUHandle    string         `yaml:"ouHandle,omitempty"`
		Members     []group.Member `yaml:"members,omitempty"`
	}
	if err := doc.Node.Decode(&raw); err != nil {
		return decodeErrorOutcome(resourceTypeGroup, raw.ID, raw.Name, err)
	}

	resolvedOUID, svcErr := s.resolveImportOUHandle(
		ctx, resourceTypeGroup, raw.ID, raw.Name, raw.OUID, raw.OUHandle)
	if svcErr != nil {
		return serviceErrorOutcome(resourceTypeGroup, raw.ID, raw.Name, operationCreate, svcErr)
	}
	raw.OUID = resolvedOUID

	req = group.CreateGroupRequest{
		ID:          raw.ID,
		Name:        raw.Name,
		Description: raw.Description,
		OUID:        raw.OUID,
	}

	updateReq := group.UpdateGroupRequest{
		Name:        raw.Name,
		Description: raw.Description,
		OUID:        raw.OUID,
	}

	if dryRun {
		if options.IsUpsertEnabled() && raw.ID != "" {
			_, svcErr := s.groupService.GetGroup(ctx, raw.ID, false)
			if svcErr == nil {
				return successOutcome(resourceTypeGroup, raw.ID, raw.Name, operationUpdate)
			}
			if !isNotFoundServiceError(svcErr) {
				return serviceErrorOutcome(resourceTypeGroup, raw.ID, raw.Name, operationUpdate, svcErr)
			}
		}
		return successOutcome(resourceTypeGroup, raw.ID, raw.Name, operationCreate)
	}

	if options.IsUpsertEnabled() && raw.ID != "" {
		_, svcErr := s.groupService.GetGroup(ctx, raw.ID, false)
		if svcErr == nil {
			updated, updateErr := s.groupService.UpdateGroup(ctx, raw.ID, updateReq)
			if updateErr != nil {
				return serviceErrorOutcome(resourceTypeGroup, raw.ID, raw.Name, operationUpdate, updateErr)
			}
			if len(raw.Members) > 0 {
				if _, memberErr := s.groupService.AddGroupMembers(ctx, updated.ID, raw.Members); memberErr != nil {
					return serviceErrorOutcome(resourceTypeGroup, updated.ID, updated.Name, operationUpdate, memberErr)
				}
			}
			return successOutcome(resourceTypeGroup, updated.ID, updated.Name, operationUpdate)
		}
		if !isNotFoundServiceError(svcErr) {
			return serviceErrorOutcome(resourceTypeGroup, raw.ID, raw.Name, operationUpdate, svcErr)
		}
	}

	grp, svcErr := s.groupService.CreateGroup(ctx, req)
	if svcErr != nil {
		return serviceErrorOutcome(resourceTypeGroup, raw.ID, raw.Name, operationCreate, svcErr)
	}
	if len(raw.Members) > 0 {
		if _, memberErr := s.groupService.AddGroupMembers(ctx, grp.ID, raw.Members); memberErr != nil {
			return serviceErrorOutcome(resourceTypeGroup, grp.ID, grp.Name, operationCreate, memberErr)
		}
	}
	return successOutcome(resourceTypeGroup, grp.ID, grp.Name, operationCreate)
}

func (s *importService) importResourceServer(
	ctx context.Context, doc parsedDocument, options *ImportOptions, dryRun bool,
) ImportItemOutcome {
	if s.resourceService == nil {
		return unsupportedAdapterOutcome(resourceTypeResourceServer, "resource server")
	}

	var req providers.ResourceServer
	if err := doc.Node.Decode(&req); err != nil {
		return decodeErrorOutcome(resourceTypeResourceServer, req.ID, req.Name, err)
	}

	resolvedOUID, svcErr := s.resolveImportOUHandle(
		ctx, resourceTypeResourceServer, req.ID, req.Name, req.OUID, req.OUHandle)
	if svcErr != nil {
		return serviceErrorOutcome(resourceTypeResourceServer, req.ID, req.Name, operationCreate, svcErr)
	}
	req.OUID = resolvedOUID

	if dryRun {
		if options.IsUpsertEnabled() && req.ID != "" {
			_, svcErr := s.resourceService.GetResourceServer(ctx, req.ID)
			if svcErr == nil {
				return successOutcome(resourceTypeResourceServer, req.ID, req.Name, operationUpdate)
			}

			if !isNotFoundServiceError(svcErr) {
				return serviceErrorOutcome(resourceTypeResourceServer, req.ID, req.Name, operationUpdate, svcErr)
			}
		}

		return successOutcome(resourceTypeResourceServer, req.ID, req.Name, operationCreate)
	}

	if options.IsUpsertEnabled() && req.ID != "" {
		updated, svcErr := s.resourceService.UpdateResourceServer(ctx, req.ID, req)
		if svcErr == nil {
			if err := s.importResourceServerChildren(ctx, updated.ID, req); err != nil {
				return serviceErrorOutcome(resourceTypeResourceServer, updated.ID, updated.Name, operationUpdate, err)
			}
			if err := s.applyResourceServerSharing(ctx, doc, updated.ID, updated.OUID); err != nil {
				return serviceErrorOutcome(resourceTypeResourceServer, updated.ID, updated.Name, operationUpdate, err)
			}
			return successOutcome(resourceTypeResourceServer, updated.ID, updated.Name, operationUpdate)
		}

		if !isNotFoundServiceError(svcErr) {
			return serviceErrorOutcome(resourceTypeResourceServer, req.ID, req.Name, operationUpdate, svcErr)
		}
	}

	created, svcErr := s.resourceService.CreateResourceServer(ctx, req)
	if svcErr != nil {
		return serviceErrorOutcome(resourceTypeResourceServer, req.ID, req.Name, operationCreate, svcErr)
	}

	if err := s.importResourceServerChildren(ctx, created.ID, req); err != nil {
		return serviceErrorOutcome(resourceTypeResourceServer, created.ID, created.Name, operationCreate, err)
	}

	if err := s.applyResourceServerSharing(ctx, doc, created.ID, created.OUID); err != nil {
		return serviceErrorOutcome(resourceTypeResourceServer, created.ID, created.Name, operationCreate, err)
	}

	return successOutcome(resourceTypeResourceServer, created.ID, created.Name, operationCreate)
}

// applyResourceServerSharing replays a declaratively-declared resource server's grants
// through resourceService.ShareResourceServer, so they pass the same eligibility checks and take
// the same cascade a live POST /resource-servers/{id}/grants call would. A no-op when the
// document declares none.
//
// Cascading is the whole point of going through the resource service rather than calling
// sharingService.Share directly (which is what the role path does): a resource server has no
// permission string of its own, its permissions are its resources and actions. A grant on the
// server row alone satisfies FilterVisiblePermissions' server-level gate but fails the
// per-permission node check, so every permission the server defines would still be invisible and
// every role naming one would be rejected with ROL-1025. See §4.6 and §5.1 of
//
// Unlike applyRoleSharing this is idempotent: bootstrap and import both run repeatedly against an
// existing deployment (bootstrap is upsert-based by design), and Share() itself does not dedupe,
// so replaying unconditionally would append a fresh duplicate grant row on every run. Grants
// already present are therefore skipped, compared against ExportGrants' replayable form, which is
// exactly the shape being replayed.
func (s *importService) applyResourceServerSharing(
	ctx context.Context, doc parsedDocument, id, ownerOUID string,
) *tidcommon.ServiceError {
	var sharingBlock resourceServerSharingYAML
	if err := doc.Node.Decode(&sharingBlock); err != nil {
		return tidcommon.CustomServiceError(tidcommon.InternalServerError,
			tidcommon.I18nMessage{DefaultValue: "failed to decode resource server grants: " + err.Error()})
	}
	if len(sharingBlock.Grants) == 0 {
		return nil
	}
	if s.sharingService == nil {
		return tidcommon.CustomServiceError(tidcommon.InternalServerError,
			tidcommon.I18nMessage{DefaultValue: "sharingService not configured"})
	}

	existing, svcErr := s.sharingService.ExportGrants(
		ctx, sharing.ResourceType(resourceTypeResourceServer), id)
	if svcErr != nil {
		return svcErr
	}

	for _, grant := range sharingBlock.Grants {
		actingOUID := grant.OUID
		if actingOUID == "" {
			actingOUID = ownerOUID
		}
		if replayableGrantPresent(existing, actingOUID, grant.ToSharePolicy()) {
			continue
		}
		if _, svcErr := s.resourceService.ShareResourceServer(ctx, id, grant); svcErr != nil {
			return svcErr
		}
	}
	return nil
}

// replayableGrantPresent reports whether existing already contains a grant equivalent to the one
// (actingOUID, policy) would create. Slice fields are compared as sets, since neither the grant
// store nor ExportGrants promises to preserve the order they were declared in.
func replayableGrantPresent(
	existing []sharing.ReplayableGrant, actingOUID string, policy sharing.SharePolicy,
) bool {
	for _, e := range existing {
		if e.ActingOUID != actingOUID {
			continue
		}
		p := e.Policy
		if p.AllOUs == policy.AllOUs && p.AllRoots == policy.AllRoots && p.AllChildren == policy.AllChildren &&
			sameStringSet(p.RootOUIDs, policy.RootOUIDs) &&
			sameStringSet(p.OUIDs, policy.OUIDs) &&
			sameStringSet(p.ExcludedRootOUIDs, policy.ExcludedRootOUIDs) &&
			sameStringSet(p.ExcludedOUIDs, policy.ExcludedOUIDs) &&
			sameStringSet(p.EditableFields, policy.EditableFields) {
			return true
		}
	}
	return false
}

// sameStringSet reports whether a and b contain the same elements, ignoring order and duplicates.
func sameStringSet(a, b []string) bool {
	set := make(map[string]struct{}, len(a))
	for _, v := range a {
		set[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := set[v]; !ok {
			return false
		}
		delete(set, v)
	}
	return len(set) == 0
}

//nolint:dupl // Theme and layout imports share the same upsert pattern with type-specific services.
func (s *importService) importTheme(
	ctx context.Context, doc parsedDocument, options *ImportOptions, dryRun bool) ImportItemOutcome {
	if s.themeService == nil {
		return unsupportedAdapterOutcome(resourceTypeTheme, "theme")
	}

	var req themeDeclarativeYAML
	if err := doc.Node.Decode(&req); err != nil {
		return decodeErrorOutcome(resourceTypeTheme, req.ID, req.DisplayName, err)
	}

	themeBytes, err := json.Marshal(req.Theme)
	if err != nil {
		return ImportItemOutcome{
			ResourceType: resourceTypeTheme,
			ResourceID:   req.ID,
			ResourceName: req.DisplayName,
			Status:       statusFailed,
			Code:         ErrorInvalidYAMLContent.Code,
			Message:      fmt.Sprintf("failed to marshal theme: %v", err),
		}
	}

	createReq := thememgt.CreateThemeRequestWithID{
		ID:          req.ID,
		Handle:      req.Handle,
		DisplayName: req.DisplayName,
		Description: req.Description,
		Theme:       themeBytes,
	}
	updateReq := thememgt.UpdateThemeRequest{
		Handle:      req.Handle,
		DisplayName: req.DisplayName,
		Description: req.Description,
		Theme:       themeBytes,
	}

	if dryRun {
		if options.IsUpsertEnabled() && req.ID != "" {
			_, svcErr := s.themeService.GetTheme(ctx, req.ID)
			if svcErr == nil {
				return successOutcome(resourceTypeTheme, req.ID, req.DisplayName, operationUpdate)
			}

			if !isNotFoundServiceError(svcErr) {
				return serviceErrorOutcome(resourceTypeTheme, req.ID, req.DisplayName, operationUpdate, svcErr)
			}
		}

		return successOutcome(resourceTypeTheme, req.ID, req.DisplayName, operationCreate)
	}

	if options.IsUpsertEnabled() && req.ID != "" {
		updated, svcErr := s.themeService.UpdateTheme(ctx, req.ID, updateReq)
		if svcErr == nil {
			return successOutcome(resourceTypeTheme, updated.ID, updated.DisplayName, operationUpdate)
		}

		if !isNotFoundServiceError(svcErr) {
			return serviceErrorOutcome(resourceTypeTheme, req.ID, req.DisplayName, operationUpdate, svcErr)
		}

		created, createErr := s.themeService.CreateTheme(ctx, createReq)
		if createErr != nil {
			return serviceErrorOutcome(resourceTypeTheme, req.ID, req.DisplayName, operationCreate, createErr)
		}

		return successOutcome(resourceTypeTheme, created.ID, created.DisplayName, operationCreate)
	}

	created, svcErr := s.themeService.CreateTheme(ctx, createReq)
	if svcErr != nil {
		return serviceErrorOutcome(resourceTypeTheme, req.ID, req.DisplayName, operationCreate, svcErr)
	}

	return successOutcome(resourceTypeTheme, created.ID, created.DisplayName, operationCreate)
}

//nolint:dupl // Theme and layout imports share the same upsert pattern with type-specific services.
func (s *importService) importLayout(
	ctx context.Context, doc parsedDocument, options *ImportOptions, dryRun bool) ImportItemOutcome {
	if s.layoutService == nil {
		return unsupportedAdapterOutcome(resourceTypeLayout, "layout")
	}

	var req layoutDeclarativeYAML
	if err := doc.Node.Decode(&req); err != nil {
		return decodeErrorOutcome(resourceTypeLayout, req.ID, req.DisplayName, err)
	}

	layoutBytes, err := json.Marshal(req.Layout)
	if err != nil {
		return ImportItemOutcome{
			ResourceType: resourceTypeLayout,
			ResourceID:   req.ID,
			ResourceName: req.DisplayName,
			Status:       statusFailed,
			Code:         ErrorInvalidYAMLContent.Code,
			Message:      fmt.Sprintf("failed to marshal layout: %v", err),
		}
	}

	createReq := layoutmgt.CreateLayoutRequestWithID{
		ID:          req.ID,
		Handle:      req.Handle,
		DisplayName: req.DisplayName,
		Description: req.Description,
		Layout:      layoutBytes,
	}
	updateReq := layoutmgt.UpdateLayoutRequest{
		Handle:      req.Handle,
		DisplayName: req.DisplayName,
		Description: req.Description,
		Layout:      layoutBytes,
	}

	if dryRun {
		if options.IsUpsertEnabled() && req.ID != "" {
			_, svcErr := s.layoutService.GetLayout(ctx, req.ID)
			if svcErr == nil {
				return successOutcome(resourceTypeLayout, req.ID, req.DisplayName, operationUpdate)
			}

			if !isNotFoundServiceError(svcErr) {
				return serviceErrorOutcome(resourceTypeLayout, req.ID, req.DisplayName, operationUpdate, svcErr)
			}
		}

		return successOutcome(resourceTypeLayout, req.ID, req.DisplayName, operationCreate)
	}

	if options.IsUpsertEnabled() && req.ID != "" {
		updated, svcErr := s.layoutService.UpdateLayout(ctx, req.ID, updateReq)
		if svcErr == nil {
			return successOutcome(resourceTypeLayout, updated.ID, updated.DisplayName, operationUpdate)
		}

		if !isNotFoundServiceError(svcErr) {
			return serviceErrorOutcome(resourceTypeLayout, req.ID, req.DisplayName, operationUpdate, svcErr)
		}

		created, createErr := s.layoutService.CreateLayout(ctx, createReq)
		if createErr != nil {
			return serviceErrorOutcome(resourceTypeLayout, req.ID, req.DisplayName, operationCreate, createErr)
		}

		return successOutcome(resourceTypeLayout, created.ID, created.DisplayName, operationCreate)
	}

	created, svcErr := s.layoutService.CreateLayout(ctx, createReq)
	if svcErr != nil {
		return serviceErrorOutcome(resourceTypeLayout, req.ID, req.DisplayName, operationCreate, svcErr)
	}

	return successOutcome(resourceTypeLayout, created.ID, created.DisplayName, operationCreate)
}

func (s *importService) importUser(
	ctx context.Context, doc parsedDocument, options *ImportOptions, dryRun bool,
) ImportItemOutcome {
	if s.userService == nil {
		return unsupportedAdapterOutcome(resourceTypeUser, "user")
	}

	var req userDeclarativeYAML
	if err := doc.Node.Decode(&req); err != nil {
		return decodeErrorOutcome(resourceTypeUser, req.ID, "", err)
	}

	resolvedOUID, svcErr := s.resolveImportOUHandle(
		ctx, resourceTypeUser, req.ID, "", req.OUID, req.OUHandle)
	if svcErr != nil {
		return serviceErrorOutcome(resourceTypeUser, req.ID, "", operationCreate, svcErr)
	}
	req.OUID = resolvedOUID

	attributesJSON, err := json.Marshal(req.Attributes)
	if err != nil {
		return ImportItemOutcome{ResourceType: resourceTypeUser, ResourceID: req.ID, Status: statusFailed,
			Code: ErrorInvalidYAMLContent.Code, Message: fmt.Sprintf("failed to marshal user attributes: %v", err)}
	}

	userReq := &providers.User{
		ID:         req.ID,
		OUID:       req.OUID,
		Type:       req.Type,
		Attributes: attributesJSON,
	}

	credentialsJSON, err := json.Marshal(req.Credentials)
	if err != nil {
		return ImportItemOutcome{ResourceType: resourceTypeUser, ResourceID: req.ID, Status: statusFailed,
			Code: ErrorInvalidYAMLContent.Code, Message: fmt.Sprintf("failed to marshal user credentials: %v", err)}
	}

	if dryRun {
		if options.IsUpsertEnabled() && req.ID != "" {
			_, svcErr := s.userService.GetUser(ctx, req.ID, false)
			if svcErr == nil {
				return successOutcome(resourceTypeUser, req.ID, "", operationUpdate)
			}

			if !isNotFoundServiceError(svcErr) {
				return serviceErrorOutcome(resourceTypeUser, req.ID, "", operationUpdate, svcErr)
			}
		}

		return successOutcome(resourceTypeUser, req.ID, "", operationCreate)
	}

	if options.IsUpsertEnabled() && req.ID != "" {
		updated, svcErr := s.userService.UpdateUser(ctx, req.ID, userReq)
		if svcErr == nil {
			if len(credentialsJSON) > 0 && string(credentialsJSON) != "null" && string(credentialsJSON) != "{}" {
				if credErr := s.userService.UpdateUserCredentials(
					ctx,
					req.ID,
					json.RawMessage(credentialsJSON),
				); credErr != nil {
					// Profile is already committed; emit a clear partial-failure outcome.
					return ImportItemOutcome{
						ResourceType: resourceTypeUser,
						ResourceID:   req.ID,
						Operation:    operationUpdate,
						Status:       statusFailed,
						Code:         credErr.Code,
						Message: "user profile updated but credential update failed: " +
							credErr.Error.DefaultValue,
					}
				}
			}
			return successOutcome(resourceTypeUser, updated.ID, "", operationUpdate)
		}

		if !isNotFoundServiceError(svcErr) {
			return serviceErrorOutcome(resourceTypeUser, req.ID, "", operationUpdate, svcErr)
		}
	}

	created, svcErr := s.userService.CreateUser(ctx, userReq)
	if svcErr != nil {
		return serviceErrorOutcome(resourceTypeUser, req.ID, "", operationCreate, svcErr)
	}
	if len(credentialsJSON) > 0 && string(credentialsJSON) != "null" && string(credentialsJSON) != "{}" {
		if credErr := s.userService.UpdateUserCredentials(
			ctx,
			created.ID,
			json.RawMessage(credentialsJSON),
		); credErr != nil {
			if rollbackErr := s.userService.DeleteUser(ctx, created.ID); rollbackErr != nil {
				combinedErr := &tidcommon.ServiceError{
					Code: credErr.Code,
					Type: credErr.Type,
					Error: tidcommon.I18nMessage{
						Key: credErr.Error.Key,
						DefaultValue: fmt.Sprintf(
							"user credential update failed: %s; rollback delete failed: %s",
							credErr.Error.DefaultValue,
							rollbackErr.Error.DefaultValue,
						),
					},
					ErrorDescription: tidcommon.I18nMessage{
						Key: credErr.ErrorDescription.Key,
						DefaultValue: fmt.Sprintf(
							"credential update error code %s for user %s; rollback delete error code %s",
							credErr.Code,
							created.ID,
							rollbackErr.Code,
						),
					},
				}

				return serviceErrorOutcome(resourceTypeUser, created.ID, "", operationCreate, combinedErr)
			}

			return serviceErrorOutcome(resourceTypeUser, created.ID, "", operationCreate, credErr)
		}
	}

	return successOutcome(resourceTypeUser, created.ID, "", operationCreate)
}

func (s *importService) importTranslation(ctx context.Context, doc parsedDocument, dryRun bool) ImportItemOutcome {
	if s.translationService == nil {
		return unsupportedAdapterOutcome(resourceTypeTranslation, "translation")
	}

	var req i18nmgt.LanguageTranslations
	if err := doc.Node.Decode(&req); err != nil {
		return decodeErrorOutcome(resourceTypeTranslation, "", req.Language, err)
	}

	if dryRun {
		return successOutcome(resourceTypeTranslation, "", req.Language, operationUpdate)
	}

	_, i18nErr := s.translationService.SetTranslationOverrides(ctx, req.Language, req.Translations)
	if i18nErr != nil {
		return ImportItemOutcome{
			ResourceType: resourceTypeTranslation,
			ResourceName: req.Language,
			Operation:    operationUpdate,
			Status:       statusFailed,
			Code:         i18nErr.Code,
			Message:      i18nErr.Error.DefaultValue,
		}
	}

	return successOutcome(resourceTypeTranslation, "", req.Language, operationUpdate)
}

// importResourceServerChildren creates resources and actions nested under a resource server.
// It first computes permission strings via ProcessResourceServer, then calls the resource service
// for each resource and action.  Existing resources/actions (on upsert paths) are silently skipped.
func (s *importService) importResourceServerChildren(
	ctx context.Context, serverID string, rs providers.ResourceServer,
) *tidcommon.ServiceError {
	if len(rs.Resources) == 0 {
		return nil
	}

	// Compute permission strings in-place (mirrors declarative loader logic).
	if err := resource.ProcessResourceServer(&rs); err != nil {
		return &tidcommon.ServiceError{
			Code: ErrorInvalidYAMLContent.Code,
			Type: ErrorInvalidYAMLContent.Type,
			Error: tidcommon.I18nMessage{
				DefaultValue: fmt.Sprintf("failed to process resource server children: %v", err),
			},
		}
	}

	// handleToID maps resource handle → created/resolved ID for parent resolution.
	handleToID := make(map[string]string)

	for i := range rs.Resources {
		res := rs.Resources[i]

		// Resolve ParentHandle to the parent ID using handles seen so far in this import.
		if res.ParentHandle != "" {
			if parentID, ok := handleToID[res.ParentHandle]; ok {
				res.Parent = &parentID
			}
		}

		created, svcErr := s.resourceService.CreateResource(ctx, serverID, res)
		if svcErr != nil {
			if svcErr.Code != resource.ErrorHandleConflict.Code {
				return svcErr
			}
			// Resource already exists — look it up under the same parent scope to get its ID.
			var parentID *string
			if res.ParentHandle != "" {
				if pid, ok := handleToID[res.ParentHandle]; ok {
					parentID = &pid
				}
			}
			list, listErr := s.resourceService.GetResourceList(ctx, serverID, parentID, serverconst.MaxPageSize, 0)
			if listErr != nil {
				return listErr
			}
			var existingID string
			for j := range list.Resources {
				if list.Resources[j].Handle == res.Handle {
					existingID = list.Resources[j].ID
					break
				}
			}
			if existingID == "" {
				continue
			}
			created = &providers.Resource{ID: existingID}
		}

		handleToID[res.Handle] = created.ID

		for j := range res.Actions {
			action := res.Actions[j]
			_, actionErr := s.resourceService.CreateAction(ctx, serverID, &created.ID, action)
			if actionErr != nil && actionErr.Code != resource.ErrorHandleConflict.Code {
				return actionErr
			}
		}
	}

	return nil
}

func (s *importService) importAgent(
	ctx context.Context, doc parsedDocument, options *ImportOptions, dryRun bool, flowIDAliases map[string]string,
) ImportItemOutcome {
	if s.agentService == nil {
		return unsupportedAdapterOutcome(resourceTypeAgent, "agent")
	}

	var req agentmodel.AgentRequestWithID
	if err := doc.Node.Decode(&req); err != nil {
		return decodeErrorOutcome(resourceTypeAgent, req.ID, req.Name, err)
	}

	if mappedFlowID, ok := flowIDAliases[req.AuthFlowID]; ok {
		req.AuthFlowID = mappedFlowID
	}
	if mappedFlowID, ok := flowIDAliases[req.RegistrationFlowID]; ok {
		req.RegistrationFlowID = mappedFlowID
	}

	var attributesJSON json.RawMessage
	if len(req.Attributes) > 0 {
		raw, err := json.Marshal(req.Attributes)
		if err != nil {
			return ImportItemOutcome{
				ResourceType: resourceTypeAgent,
				ResourceID:   req.ID,
				ResourceName: req.Name,
				Status:       statusFailed,
				Code:         ErrorInvalidYAMLContent.Code,
				Message:      fmt.Sprintf("failed to marshal agent attributes: %v", err),
			}
		}
		attributesJSON = raw
	}

	normalizeAgentOAuthConfigForImport(ctx, &req)

	createReq := &providers.Agent{
		ID:          req.ID,
		OUID:        req.OUID,
		OUHandle:    req.OUHandle,
		Type:        req.Type,
		Name:        req.Name,
		Description: req.Description,
		LogoURL:     req.LogoURL,
		Owner:       req.Owner,
		Attributes:  attributesJSON,
		InboundAuthProfile: providers.InboundAuthProfile{
			AuthFlowID:                req.AuthFlowID,
			AuthFlowHandle:            req.AuthFlowHandle,
			RegistrationFlowID:        req.RegistrationFlowID,
			RegistrationFlowHandle:    req.RegistrationFlowHandle,
			IsRegistrationFlowEnabled: req.IsRegistrationFlowEnabled,
			RecoveryFlowID:            req.RecoveryFlowID,
			RecoveryFlowHandle:        req.RecoveryFlowHandle,
			IsRecoveryFlowEnabled:     req.IsRecoveryFlowEnabled,
			SignOutFlowID:             req.SignOutFlowID,
			SignOutFlowHandle:         req.SignOutFlowHandle,
			ThemeID:                   req.ThemeID,
			LayoutID:                  req.LayoutID,
			Assertion:                 req.Assertion,
			LoginConsent:              req.LoginConsent,
			AllowedUserTypes:          req.AllowedUserTypes,
			AllowedAgentTypes:         req.AllowedAgentTypes,
			PasskeyAllowedOrigins:     req.PasskeyAllowedOrigins,
			Attestation:               req.Attestation,
		},
		InboundAuthConfig: req.InboundAuthConfig,
	}
	updateReq := &agentmodel.UpdateAgentRequest{
		OUID:                  req.OUID,
		OUHandle:              req.OUHandle,
		Type:                  req.Type,
		Name:                  req.Name,
		Description:           req.Description,
		LogoURL:               req.LogoURL,
		Owner:                 req.Owner,
		Attributes:            attributesJSON,
		InboundAuthProfileReq: req.InboundAuthProfileReq,
		InboundAuthConfig:     req.InboundAuthConfig,
	}

	if dryRun {
		if options.IsUpsertEnabled() && req.ID != "" {
			_, svcErr := s.agentService.GetAgent(ctx, req.ID, false)
			if svcErr == nil {
				return successOutcome(resourceTypeAgent, req.ID, req.Name, operationUpdate)
			}

			if !isNotFoundServiceError(svcErr) {
				return serviceErrorOutcome(resourceTypeAgent, req.ID, req.Name, operationUpdate, svcErr)
			}
		}

		return successOutcome(resourceTypeAgent, req.ID, req.Name, operationCreate)
	}

	if options.IsUpsertEnabled() && req.ID != "" {
		_, svcErr := s.agentService.GetAgent(ctx, req.ID, false)
		if svcErr == nil {
			updated, updateErr := s.agentService.UpdateAgent(ctx, req.ID, updateReq)
			if updateErr != nil {
				return serviceErrorOutcome(resourceTypeAgent, req.ID, req.Name, operationUpdate, updateErr)
			}
			return successOutcome(resourceTypeAgent, updated.ID, updated.Name, operationUpdate)
		}

		if !isNotFoundServiceError(svcErr) {
			return serviceErrorOutcome(resourceTypeAgent, req.ID, req.Name, operationUpdate, svcErr)
		}
	}

	created, svcErr := s.agentService.CreateAgent(ctx, createReq)
	if svcErr != nil {
		return serviceErrorOutcome(resourceTypeAgent, req.ID, req.Name, operationCreate, svcErr)
	}
	return successOutcome(resourceTypeAgent, created.ID, created.Name, operationCreate)
}

func getAgentOAuthConfigForImport(req *agentmodel.AgentRequestWithID) *providers.OAuthConfigWithSecret {
	if req == nil {
		return nil
	}

	for _, inboundAuth := range req.InboundAuthConfig {
		if inboundAuth.Type == providers.OAuthInboundAuthType && inboundAuth.OAuthConfig != nil {
			return inboundAuth.OAuthConfig
		}
	}

	return nil
}

func normalizeAgentOAuthConfigForImport(ctx context.Context, req *agentmodel.AgentRequestWithID) {
	oauthConfig := getAgentOAuthConfigForImport(req)
	if oauthConfig == nil {
		return
	}

	if oauthConfig.PublicClient &&
		oauthConfig.TokenEndpointAuthMethod == providers.TokenEndpointAuthMethodNone &&
		oauthConfig.ClientSecret != "" {
		log.GetLogger().Debug(ctx,
			"Dropping client_secret for public agent import with token endpoint auth method 'none'",
			log.String("agentID", req.ID),
			log.String("name", req.Name),
			log.String("clientID", oauthConfig.ClientID))
		oauthConfig.ClientSecret = ""
	}
}

func unsupportedAdapterOutcome(resourceType, name string) ImportItemOutcome {
	return ImportItemOutcome{
		ResourceType: resourceType,
		Status:       statusFailed,
		Code:         ErrorInvalidImportRequest.Code,
		Message:      name + " adapter is not configured",
	}
}

func decodeErrorOutcome(resourceType, id, name string, err error) ImportItemOutcome {
	return ImportItemOutcome{
		ResourceType: resourceType,
		ResourceID:   id,
		ResourceName: name,
		Status:       statusFailed,
		Code:         ErrorInvalidYAMLContent.Code,
		Message:      fmt.Sprintf("failed to decode %s document: %v", resourceType, err),
	}
}

func serviceErrorOutcome(
	resourceType, id, name, operation string,
	svcErr *tidcommon.ServiceError,
) ImportItemOutcome {
	return ImportItemOutcome{
		ResourceType: resourceType,
		ResourceID:   id,
		ResourceName: name,
		Operation:    operation,
		Status:       statusFailed,
		Code:         svcErr.Code,
		Message:      svcErr.Error.DefaultValue,
	}
}

func successOutcome(resourceType, id, name, operation string) ImportItemOutcome {
	return ImportItemOutcome{
		ResourceType: resourceType,
		ResourceID:   id,
		ResourceName: name,
		Operation:    operation,
		Status:       statusSuccess,
	}
}

//nolint:dupl // parallel to importCredentialConfiguration; kept separate per resource type.
func (s *importService) importPresentationDefinition(
	ctx context.Context, doc parsedDocument, options *ImportOptions, dryRun bool,
) ImportItemOutcome {
	if s.presentationDefinitionService == nil {
		return ImportItemOutcome{
			ResourceType: resourceTypePresentationDefinition,
			Status:       statusFailed,
			Code:         ErrorAdapterNotConfigured.Code,
			Message:      "presentation definition adapter is not configured",
		}
	}

	var dto presentation.PresentationDefinitionDTO
	if err := doc.Node.Decode(&dto); err != nil {
		return ImportItemOutcome{
			ResourceType: resourceTypePresentationDefinition,
			Status:       statusFailed,
			Code:         ErrorInvalidYAMLContent.Code,
			Message:      fmt.Sprintf("failed to decode presentation definition document: %v", err),
		}
	}

	resolvedOUID, svcErr := s.resolveImportOUHandle(
		ctx, resourceTypePresentationDefinition, dto.ID, dto.Handle, dto.OUID, dto.OUHandle)
	if svcErr != nil {
		return serviceErrorOutcome(
			resourceTypePresentationDefinition, dto.ID, dto.Handle, operationCreate, svcErr)
	}
	dto.OUID = resolvedOUID

	if dryRun {
		if options.IsUpsertEnabled() && dto.ID != "" {
			_, svcErr := s.presentationDefinitionService.GetPresentationDefinition(ctx, dto.ID)
			if svcErr == nil {
				return successOutcome(resourceTypePresentationDefinition, dto.ID, dto.Handle, operationUpdate)
			}
			if !isNotFoundServiceError(svcErr) {
				return serviceErrorOutcome(
					resourceTypePresentationDefinition, dto.ID, dto.Handle, operationUpdate, svcErr)
			}
		}
		return successOutcome(resourceTypePresentationDefinition, dto.ID, dto.Handle, operationCreate)
	}

	if options.IsUpsertEnabled() && dto.ID != "" {
		updated, svcErr := s.presentationDefinitionService.UpdatePresentationDefinition(ctx, dto.ID, &dto)
		if svcErr == nil {
			return successOutcome(resourceTypePresentationDefinition, updated.ID, updated.Handle, operationUpdate)
		}
		if !isNotFoundServiceError(svcErr) {
			return serviceErrorOutcome(
				resourceTypePresentationDefinition, dto.ID, dto.Handle, operationUpdate, svcErr)
		}
	}

	created, svcErr := s.presentationDefinitionService.CreatePresentationDefinition(ctx, &dto)
	if svcErr != nil {
		return serviceErrorOutcome(resourceTypePresentationDefinition, dto.ID, dto.Handle, operationCreate, svcErr)
	}
	return successOutcome(resourceTypePresentationDefinition, created.ID, created.Handle, operationCreate)
}

//nolint:dupl // parallel to importPresentationDefinition; kept separate per resource type.
func (s *importService) importCredentialConfiguration(
	ctx context.Context, doc parsedDocument, options *ImportOptions, dryRun bool,
) ImportItemOutcome {
	if s.credentialConfigurationService == nil {
		return ImportItemOutcome{
			ResourceType: resourceTypeCredentialConfiguration,
			Status:       statusFailed,
			Code:         ErrorAdapterNotConfigured.Code,
			Message:      "credential configuration adapter is not configured",
		}
	}

	var dto credential.CredentialConfigurationDTO
	if err := doc.Node.Decode(&dto); err != nil {
		return ImportItemOutcome{
			ResourceType: resourceTypeCredentialConfiguration,
			Status:       statusFailed,
			Code:         ErrorInvalidYAMLContent.Code,
			Message:      fmt.Sprintf("failed to decode credential configuration document: %v", err),
		}
	}

	resolvedOUID, svcErr := s.resolveImportOUHandle(
		ctx, resourceTypeCredentialConfiguration, dto.ID, dto.Handle, dto.OUID, dto.OUHandle)
	if svcErr != nil {
		return serviceErrorOutcome(resourceTypeCredentialConfiguration, dto.ID, dto.Handle, operationCreate, svcErr)
	}
	dto.OUID = resolvedOUID

	if dryRun {
		if options.IsUpsertEnabled() && dto.ID != "" {
			_, svcErr := s.credentialConfigurationService.GetCredentialConfiguration(ctx, dto.ID)
			if svcErr == nil {
				return successOutcome(resourceTypeCredentialConfiguration, dto.ID, dto.Handle, operationUpdate)
			}
			if !isNotFoundServiceError(svcErr) {
				return serviceErrorOutcome(
					resourceTypeCredentialConfiguration, dto.ID, dto.Handle, operationUpdate, svcErr)
			}
		}
		return successOutcome(resourceTypeCredentialConfiguration, dto.ID, dto.Handle, operationCreate)
	}

	if options.IsUpsertEnabled() && dto.ID != "" {
		updated, svcErr := s.credentialConfigurationService.UpdateCredentialConfiguration(ctx, dto.ID, &dto)
		if svcErr == nil {
			return successOutcome(resourceTypeCredentialConfiguration, updated.ID, updated.Handle, operationUpdate)
		}
		if !isNotFoundServiceError(svcErr) {
			return serviceErrorOutcome(
				resourceTypeCredentialConfiguration, dto.ID, dto.Handle, operationUpdate, svcErr)
		}
	}

	created, svcErr := s.credentialConfigurationService.CreateCredentialConfiguration(ctx, &dto)
	if svcErr != nil {
		return serviceErrorOutcome(resourceTypeCredentialConfiguration, dto.ID, dto.Handle, operationCreate, svcErr)
	}
	return successOutcome(resourceTypeCredentialConfiguration, created.ID, created.Handle, operationCreate)
}
