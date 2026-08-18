// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"context"
	"fmt"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"

	"gopkg.in/yaml.v3"

	"github.com/thunder-id/thunderid/internal/sharing"
	serverconst "github.com/thunder-id/thunderid/internal/system/constants"
	declarativeresource "github.com/thunder-id/thunderid/internal/system/declarative_resource"
	"github.com/thunder-id/thunderid/internal/system/log"
)

const (
	resourceTypeRole = "role"
	paramTypeRole    = "Role"
)

// roleExporter implements declarativeresource.ResourceExporter for roles.
type roleExporter struct {
	service           RoleServiceInterface
	assignmentService RoleAssignmentServiceInterface
	sharingService    sharing.ServiceInterface
}

// newRoleExporter creates a new role exporter.
func newRoleExporter(
	service RoleServiceInterface,
	assignmentService RoleAssignmentServiceInterface,
	sharingService sharing.ServiceInterface,
) *roleExporter {
	return &roleExporter{service: service, assignmentService: assignmentService, sharingService: sharingService}
}

// GetResourceType returns the resource type for roles.
func (e *roleExporter) GetResourceType() string {
	return resourceTypeRole
}

// GetParameterizerType returns the parameterizer type for roles.
func (e *roleExporter) GetParameterizerType() string {
	return paramTypeRole
}

// GetAllResourceIDs retrieves all role IDs from the database store.
// In composite mode, this excludes declarative (YAML-based) roles.
func (e *roleExporter) GetAllResourceIDs(ctx context.Context) ([]string, *tidcommon.ServiceError) {
	offset := 0
	limit := serverconst.MaxPageSize
	ids := []string{}

	for {
		roles, err := e.service.GetRoleList(ctx, limit, offset)
		if err != nil {
			return nil, err
		}

		for _, role := range roles.Roles {
			isDeclarative, svcErr := e.service.IsRoleDeclarative(ctx, role.ID)
			if svcErr != nil {
				return nil, svcErr
			}
			if !isDeclarative {
				ids = append(ids, role.ID)
			}
		}

		offset += len(roles.Roles)

		// Continue fetching while we get results; stop only on empty page
		if len(roles.Roles) == 0 {
			break
		}
	}

	return ids, nil
}

// GetResourceByID retrieves a role by its ID.
func (e *roleExporter) GetResourceByID(
	ctx context.Context, id string) (interface{}, string, *tidcommon.ServiceError) {
	roleWithPermissions, err := e.service.GetRoleWithPermissions(ctx, id)
	if err != nil {
		return nil, "", err
	}

	assignments, err := e.getAssignments(ctx, id, roleWithPermissions.OUID)
	if err != nil {
		return nil, "", err
	}

	grants, err := e.getGrants(ctx, id)
	if err != nil {
		return nil, "", err
	}

	perms := make([]roleDeclarativePermission, 0, len(roleWithPermissions.Permissions))
	for _, p := range roleWithPermissions.Permissions {
		perms = append(perms, roleDeclarativePermission(p))
	}

	role := &roleDeclarativeResource{
		ID:          roleWithPermissions.ID,
		Name:        roleWithPermissions.Name,
		Description: roleWithPermissions.Description,
		OUID:        roleWithPermissions.OUID,
		Permissions: perms,
		Assignments: assignments,
		Grants:      grants,
	}

	return role, role.Name, nil
}

// getAssignments exports every assignment of the role as one flat list, each stamped with the OU
// that made it: the owning OU's own first, then each sharee OU's independent set. The ouId is always
// written out on export even though it is optional on import, so a round-trip reproduces the exact
// assigning OU rather than re-deriving it from where the assignee happens to live.
func (e *roleExporter) getAssignments(
	ctx context.Context, roleID, owningOUID string,
) ([]RoleAssignment, *tidcommon.ServiceError) {
	ouIDs, err := e.assignmentService.GetAssigningOUIDs(ctx, roleID)
	if err != nil {
		return nil, err
	}

	ordered := make([]string, 0, len(ouIDs)+1)
	ordered = append(ordered, owningOUID)
	for _, ouID := range ouIDs {
		if ouID != owningOUID {
			ordered = append(ordered, ouID)
		}
	}

	assignments := make([]RoleAssignment, 0, len(ordered))
	for _, ouID := range ordered {
		ouAssignments, err := e.getAllRoleAssignments(ctx, roleID, ouID)
		if err != nil {
			return nil, err
		}
		for _, a := range ouAssignments {
			a.OUID = ouID
			assignments = append(assignments, a)
		}
	}

	return assignments, nil
}

// getGrants exports the role's grants as replayable ShareRequests, in an order safe to
// apply sequentially (a reshare is always ordered after the grant that made its issuing OU visible).
func (e *roleExporter) getGrants(ctx context.Context, roleID string) ([]ShareRequest, *tidcommon.ServiceError) {
	replayable, err := e.sharingService.ExportGrants(ctx, roleSharingResourceType, roleID)
	if err != nil {
		return nil, err
	}

	grants := make([]ShareRequest, 0, len(replayable))
	for _, g := range replayable {
		grants = append(grants, shareRequestFromReplayableGrant(g))
	}

	return grants, nil
}

// ValidateResource validates a role resource.
func (e *roleExporter) ValidateResource(ctx context.Context,
	resource interface{}, id string, logger *log.Logger,
) (string, *declarativeresource.ExportError) {
	role, ok := resource.(*roleDeclarativeResource)
	if !ok {
		return "", declarativeresource.CreateTypeError(resourceTypeRole, id)
	}

	if err := declarativeresource.ValidateResourceName(ctx,
		role.Name, resourceTypeRole, id, "ROLE_VALIDATION_ERROR", logger); err != nil {
		return "", err
	}

	return role.Name, nil
}

// GetResourceRules returns the parameterization rules for roles.
func (e *roleExporter) GetResourceRules() *declarativeresource.ResourceRules {
	return &declarativeresource.ResourceRules{
		Variables:      []string{},
		ArrayVariables: []string{},
	}
}

// pendingShare captures one declaratively-declared role's grants discovered while parsing,
// for application after every role in the batch has been successfully loaded. role is the same
// pointer handed to the store, so its OUID reflects any ou_handle resolution performed by the
// validator.
type pendingShare struct {
	role   *RoleWithPermissionsAndAssignments
	grants []ShareRequest
}

// loadDeclarativeResources loads immutable role resources from files.
// The dbStore parameter is optional (can be nil) and is used for duplicate checking in composite mode.
// The service parameter is optional (can be nil) and is used to resolve ou_handle to ou_id.
func loadDeclarativeResources(
	fileStore *fileBasedStore, dbStore roleStoreInterface, service RoleServiceInterface,
	sharingService sharing.ServiceInterface, assignmentService RoleAssignmentServiceInterface,
) error {
	var pending []pendingShare
	var loaded []*RoleWithPermissionsAndAssignments

	resourceConfig := declarativeresource.ResourceConfig{
		ResourceType:  "Role",
		DirectoryName: "roles",
		Parser: func(data []byte) (interface{}, error) {
			role, err := parseToRole(data)
			if err != nil {
				return nil, err
			}

			var resource roleDeclarativeResource
			if err := yaml.Unmarshal(data, &resource); err != nil {
				return nil, err
			}
			if len(resource.Grants) > 0 {
				pending = append(pending, pendingShare{role: role, grants: resource.Grants})
			}
			loaded = append(loaded, role)

			return role, nil
		},
		Validator: func(data interface{}) error {
			return validateRoleWrapper(data, fileStore, dbStore, service)
		},
		IDExtractor: func(data interface{}) string {
			// Use safe type assertion to prevent panic
			if v, ok := data.(*RoleWithPermissionsAndAssignments); ok {
				return v.ID
			}
			// Log error and return empty string if type assertion fails
			// Declarative resource loading runs during startup, outside any request.
			log.GetLogger().Error(context.Background(),
				"IDExtractor: type assertion failed for RoleWithPermissionsAndAssignments")
			return ""
		},
	}

	loader := declarativeresource.NewResourceLoader(resourceConfig, fileStore)
	if err := loader.LoadResources(); err != nil {
		return fmt.Errorf("failed to load role resources: %w", err)
	}

	if err := resolveLoadedAssignmentOUIDs(loaded, assignmentService); err != nil {
		return err
	}

	return applyPendingShares(pending, sharingService)
}

// resolveLoadedAssignmentOUIDs stamps the assigning OU onto every declaratively-loaded assignment
// that did not declare one, using the assignee's own OU. Declarative roles live in the file store
// rather than ROLE_ASSIGNMENT, so this only fills in the in-memory representation the store serves —
// but it keeps a declarative role's assignments carrying the same OU a DB-backed one would.
func resolveLoadedAssignmentOUIDs(
	loaded []*RoleWithPermissionsAndAssignments, assignmentService RoleAssignmentServiceInterface,
) error {
	if assignmentService == nil {
		return nil
	}
	for _, role := range loaded {
		if len(role.Assignments) == 0 {
			continue
		}
		resolved, svcErr := assignmentService.ResolveAssignmentOUIDs(context.Background(), role.Assignments)
		if svcErr != nil {
			return fmt.Errorf("role '%s': failed to resolve assignment organization units: %s",
				role.ID, svcErr.Code)
		}
		for i := range resolved {
			if resolved[i].OUID == "" {
				resolved[i].OUID = role.OUID
			}
		}
		role.Assignments = resolved
	}
	return nil
}

// parseToRoleWrapper wraps parseToRole to match the generic Parser signature.
func parseToRoleWrapper(data []byte) (interface{}, error) {
	return parseToRole(data)
}

// applyPendingShares records every declaratively-declared grant, in declared order, through
// ShareDeclarative: the same validation Share() applies, so an ineligible declared grant still
// fails startup, but the grant is held in memory rather than written to RESOURCE_GRANT.
//
// A declarative role lives in the file store and never reaches the database, and its assignments
// are likewise only resolved in memory (see resolveLoadedAssignmentOUIDs). Persisting its grants
// alone would append a duplicate set on every restart, since Share() does not deduplicate, and
// would strand rows behind whenever the file changed.
func applyPendingShares(pending []pendingShare, sharingService sharing.ServiceInterface) error {
	for _, p := range pending {
		for _, req := range p.grants {
			actingOUID := req.InitiatingOUID
			if actingOUID == "" {
				actingOUID = p.role.OUID
			}
			if _, svcErr := sharingService.ShareDeclarative(
				context.Background(), roleSharingResourceType, p.role.ID, p.role.OUID, actingOUID, req.ToSharePolicy(),
			); svcErr != nil {
				return fmt.Errorf("role '%s': failed to apply declarative grant: %s", p.role.ID, svcErr.Code)
			}
		}
	}

	return nil
}

type roleDeclarativePermission ResourcePermissions

type roleDeclarativeResource struct {
	ID          string                      `yaml:"id"`
	Name        string                      `yaml:"name"`
	Description string                      `yaml:"description,omitempty"`
	OUID        string                      `yaml:"ouId,omitempty"`
	OUHandle    string                      `yaml:"ouHandle,omitempty"`
	Permissions []roleDeclarativePermission `yaml:"permissions"`
	// Assignments declares every assignment of the role, whichever OU made it. Each entry's optional
	// ouId is the OU the assignment is recorded under; when omitted it resolves to the assignee's own
	// OU. Sharee-OU assignments live here alongside the owner's own — there is no separate section.
	Assignments []RoleAssignment `yaml:"assignments,omitempty"`
	// Grants declares this role's grants, replayed via sharing.ServiceInterface.Share in
	// declared order when loaded declaratively (see loadDeclarativeResources), or exported here for
	// declarative round-tripping. OUID empty means "the role's own owning OU is the acting OU".
	Grants []ShareRequest `yaml:"grants,omitempty"`
}

// toResourcePermissions converts roleDeclarativePermission to ResourcePermissions.
func toResourcePermissions(perm roleDeclarativePermission) ResourcePermissions {
	return ResourcePermissions(perm)
}

// parseToRole parses YAML data to RoleWithPermissionsAndAssignments.
func parseToRole(data []byte) (*RoleWithPermissionsAndAssignments, error) {
	var roleResource roleDeclarativeResource
	if err := yaml.Unmarshal(data, &roleResource); err != nil {
		return nil, err
	}

	permissions := make([]ResourcePermissions, 0, len(roleResource.Permissions))
	for _, perm := range roleResource.Permissions {
		permissions = append(permissions, toResourcePermissions(perm))
	}

	// Translate public 'user'/'app'/'agent' assignment types to the internal 'entity' type.
	for i, a := range roleResource.Assignments {
		if a.Type.IsEntityType() {
			roleResource.Assignments[i].Type = assigneeTypeEntity
		}
	}

	role := &RoleWithPermissionsAndAssignments{
		ID:          roleResource.ID,
		Name:        roleResource.Name,
		Description: roleResource.Description,
		OUID:        roleResource.OUID,
		OUHandle:    roleResource.OUHandle,
		Permissions: permissions,
		Assignments: roleResource.Assignments,
	}

	return role, nil
}

// validateRoleWrapper validates role declarative resources and checks for duplicates.
// When a service is provided, OU handles are resolved before validation runs.
func validateRoleWrapper(
	data interface{}, fileStore *fileBasedStore, dbStore roleStoreInterface, service RoleServiceInterface,
) error {
	role, ok := data.(*RoleWithPermissionsAndAssignments)
	if !ok {
		return fmt.Errorf("invalid type: expected *RoleWithPermissionsAndAssignments")
	}

	if role.ID == "" {
		return fmt.Errorf("role ID is required")
	}
	if role.Name == "" {
		return fmt.Errorf("role name is required")
	}
	if service != nil {
		if svcErr := service.ResolveRoleOUHandle(context.Background(), role); svcErr != nil {
			return fmt.Errorf("organization unit with handle %q not found for role '%s'",
				role.OUHandle, role.Name)
		}
	}
	if role.OUID == "" {
		return fmt.Errorf("ouId or ouHandle is required for role '%s'", role.Name)
	}

	for _, assignment := range role.Assignments {
		if assignment.ID == "" {
			return fmt.Errorf("assignment ID is required")
		}
		if assignment.Type != assigneeTypeEntity && assignment.Type != AssigneeTypeGroup {
			return fmt.Errorf("invalid assignment type '%s'", assignment.Type)
		}
	}

	for _, resourcePerms := range role.Permissions {
		if resourcePerms.ResourceServerID == "" {
			return fmt.Errorf("resource server ID is required")
		}
	}

	if fileStore != nil {
		if existingData, err := fileStore.GenericFileBasedStore.Get(role.ID); err == nil && existingData != nil {
			return fmt.Errorf("duplicate role ID '%s': role already exists in declarative resources", role.ID)
		}
	}

	if dbStore != nil {
		exists, err := dbStore.IsRoleExist(context.Background(), role.ID)
		if err != nil {
			// Fail loudly on DB errors during duplicate check
			return fmt.Errorf("checking role existence for '%s': %w", role.ID, err)
		}
		if exists {
			return fmt.Errorf("duplicate role ID '%s': role already exists in the database store", role.ID)
		}
	}

	return nil
}

func (e *roleExporter) getAllRoleAssignments(
	ctx context.Context,
	roleID, ouID string,
) ([]RoleAssignment, *tidcommon.ServiceError) {
	offset := 0
	limit := serverconst.MaxPageSize
	assignments := []RoleAssignment{}

	for {
		list, err := e.assignmentService.GetRoleAssignments(ctx, roleID, ouID, limit, offset, false)
		if err != nil {
			return nil, err
		}

		for _, assignment := range list.Assignments {
			assignments = append(assignments, RoleAssignment{
				ID:   assignment.ID,
				Type: assignment.Type,
			})
		}

		offset += len(list.Assignments)

		// Continue fetching while we get results; stop only on empty page
		if len(list.Assignments) == 0 {
			break
		}
	}

	return assignments, nil
}
