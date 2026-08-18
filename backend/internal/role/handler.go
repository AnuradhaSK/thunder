// Copyright 2025 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"

	"github.com/thunder-id/thunderid/internal/sharing"
	serverconst "github.com/thunder-id/thunderid/internal/system/constants"
	"github.com/thunder-id/thunderid/internal/system/error/apierror"
	"github.com/thunder-id/thunderid/internal/system/log"
	"github.com/thunder-id/thunderid/internal/system/security"
	"github.com/thunder-id/thunderid/internal/system/sysauthz"
	sysutils "github.com/thunder-id/thunderid/internal/system/utils"
)

const handlerLoggerComponentName = "RoleHandler"

// roleHandler is the handler for role management operations.
type roleHandler struct {
	roleService       RoleServiceInterface
	assignmentService RoleAssignmentServiceInterface
	sharingService    sharing.ServiceInterface
}

// newRoleHandler creates a new instance of roleHandler
func newRoleHandler(
	roleService RoleServiceInterface,
	assignmentService RoleAssignmentServiceInterface,
	sharingService sharing.ServiceInterface,
) *roleHandler {
	return &roleHandler{
		roleService:       roleService,
		assignmentService: assignmentService,
		sharingService:    sharingService,
	}
}

// HandleRoleListRequest handles the list roles request. When the ouId query parameter is
// present, it returns the roles owned by or shared to that OU, each tagged with its origin (see
// handleRoleListForOU). Otherwise, it returns the unrestricted deployment-wide listing.
func (rh *roleHandler) HandleRoleListRequest(w http.ResponseWriter, r *http.Request) {
	if ouID := r.URL.Query().Get("ouId"); ouID != "" {
		rh.handleRoleListForOU(w, r, ouID)
		return
	}

	ctx := r.Context()
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, handlerLoggerComponentName))

	if !security.HasSystemPermission(security.GetPermissions(ctx)) {
		// A system:roles-only caller is confined to its own OU; no ouId is equivalent to
		// ?ouId=<its own OU> rather than the unrestricted deployment-wide listing below.
		rh.handleRoleListForOU(w, r, security.GetOUID(ctx))
		return
	}

	limit, offset, svcErr := parsePaginationParams(r.URL.Query())
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}

	roleList, svcErr := rh.roleService.GetRoleList(ctx, limit, offset)
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}

	// Convert service response to HTTP response
	roles := make([]RoleSummaryResponse, 0, len(roleList.Roles))
	for _, role := range roleList.Roles {
		roles = append(roles, RoleSummaryResponse(role))
	}

	roleListResponse := &RoleListResponse{
		TotalResults: roleList.TotalResults,
		StartIndex:   roleList.StartIndex,
		Count:        roleList.Count,
		Roles:        roles,
		Links:        roleList.Links,
	}

	sysutils.WriteSuccessResponse(ctx, w, http.StatusOK, roleListResponse)

	logger.Debug(ctx, "Successfully listed roles with pagination",
		log.Int("limit", limit), log.Int("offset", offset),
		log.Int("totalResults", roleListResponse.TotalResults),
		log.Int("count", roleListResponse.Count))
}

// handleRoleListForOU lists the roles owned by or shared to ouID, each tagged with its origin.
func (rh *roleHandler) handleRoleListForOU(w http.ResponseWriter, r *http.Request, ouID string) {
	ctx := r.Context()
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, handlerLoggerComponentName))

	limit, offset, svcErr := parsePaginationParams(r.URL.Query())
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}

	roleList, svcErr := rh.roleService.GetRolesForOU(ctx, ouID, limit, offset)
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}

	roles := make([]RoleSummaryForOUResponse, 0, len(roleList.Roles))
	for _, role := range roleList.Roles {
		roles = append(roles, RoleSummaryForOUResponse{
			ID:          role.ID,
			Name:        role.Name,
			Description: role.Description,
			OUID:        role.OUID,
			OUHandle:    role.OUHandle,
			IsReadOnly:  role.IsReadOnly,
			Origin:      role.Origin,
		})
	}

	sysutils.WriteSuccessResponse(ctx, w, http.StatusOK, &RoleListForOUResponse{
		TotalResults: roleList.TotalResults,
		StartIndex:   roleList.StartIndex,
		Count:        roleList.Count,
		Roles:        roles,
		Links:        roleList.Links,
	})

	logger.Debug(ctx, "Successfully listed roles for OU", log.String("ouID", ouID),
		log.Int("totalResults", roleList.TotalResults), log.Int("count", roleList.Count))
}

// HandleRolePostRequest handles the create role request.
func (rh *roleHandler) HandleRolePostRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, handlerLoggerComponentName))

	createRequest, err := sysutils.DecodeJSONBody[CreateRoleRequest](r)
	if err != nil {
		var valErr *sysutils.ValidationError
		if errors.As(err, &valErr) {
			sysutils.WriteStructuredErrorResponse(w, http.StatusBadRequest, "Validation Failed", valErr.Errors)
			return
		}
		handleError(ctx, w, &ErrorInvalidRequestFormat)
		return
	}

	sanitizedRequest := rh.sanitizeCreateRoleRequest(createRequest)

	// Convert HTTP request to service request
	serviceRequest := rh.toRoleCreationDetail(sanitizedRequest)

	serviceRole, svcErr := rh.roleService.CreateRole(ctx, serviceRequest)
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}

	// Convert service response to HTTP response
	createdRole := rh.toHTTPCreateRoleResponse(serviceRole)

	sysutils.WriteSuccessResponse(ctx, w, http.StatusCreated, createdRole)

	logger.Debug(ctx, "Successfully created role", log.String("roleId", createdRole.ID))
}

// HandleRoleGetRequest handles the get role by id request.
func (rh *roleHandler) HandleRoleGetRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, handlerLoggerComponentName))

	id := r.PathValue("id")
	serviceRole, svcErr := rh.roleService.GetRoleWithPermissions(ctx, id)
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}

	// Convert service response to HTTP response
	role := rh.toHTTPRoleResponse(serviceRole)

	sysutils.WriteSuccessResponse(ctx, w, http.StatusOK, role)

	logger.Debug(ctx, "Successfully retrieved role", log.String("role id", id))
}

// HandleRolePutRequest handles the update role request.
func (rh *roleHandler) HandleRolePutRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, handlerLoggerComponentName))

	id := r.PathValue("id")
	updateRequest, err := sysutils.DecodeJSONBody[UpdateRoleRequest](r)
	if err != nil {
		var valErr *sysutils.ValidationError
		if errors.As(err, &valErr) {
			sysutils.WriteStructuredErrorResponse(w, http.StatusBadRequest, "Validation Failed", valErr.Errors)
			return
		}
		handleError(ctx, w, &ErrorInvalidRequestFormat)
		return
	}

	sanitizedRequest := rh.sanitizeUpdateRoleRequest(updateRequest)

	// Convert HTTP request to service request
	serviceRequest := RoleUpdateDetail(sanitizedRequest)

	serviceRole, svcErr := rh.roleService.UpdateRoleWithPermissions(ctx, id, serviceRequest)
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}

	// Convert service response to HTTP response
	role := rh.toHTTPRoleResponse(serviceRole)

	sysutils.WriteSuccessResponse(ctx, w, http.StatusOK, role)

	logger.Debug(ctx, "Successfully updated role", log.String("role id", id))
}

// HandleRoleDeleteRequest handles the delete role request.
func (rh *roleHandler) HandleRoleDeleteRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, handlerLoggerComponentName))

	id := r.PathValue("id")
	svcErr := rh.roleService.DeleteRole(ctx, id)
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}

	sysutils.WriteSuccessResponse(ctx, w, http.StatusNoContent, nil)
	logger.Debug(ctx, "Successfully deleted role", log.String("role id", id))
}

// HandleRoleAssignmentsGetRequest handles the get role assignments request.
func (rh *roleHandler) HandleRoleAssignmentsGetRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, handlerLoggerComponentName))

	id := r.PathValue("id")
	limit, offset, svcErr := parsePaginationParams(r.URL.Query())
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}

	// Parse include parameter to check if display names should be included
	includeDisplay := r.URL.Query().Get(sysutils.QueryParamInclude) == sysutils.IncludeValueDisplay

	// Parse optional type parameter to filter assignments by assignee type.
	assigneeType := r.URL.Query().Get("type")
	if assigneeType != "" && assigneeType != string(AssigneeTypeUser) && assigneeType != string(AssigneeTypeGroup) &&
		assigneeType != string(AssigneeTypeApp) && assigneeType != string(AssigneeTypeAgent) {
		handleError(ctx, w, &ErrorInvalidAssigneeType)
		return
	}

	// Optional ouId: the sharee OU whose own assignments to view. Empty means the role's owner.
	ouID := r.URL.Query().Get("ouId")

	var serviceResponse *AssignmentList
	if assigneeType != "" {
		serviceResponse, svcErr = rh.assignmentService.GetRoleAssignmentsByType(
			ctx, id, ouID, limit, offset, includeDisplay, assigneeType)
	} else {
		serviceResponse, svcErr = rh.assignmentService.GetRoleAssignments(ctx, id, ouID, limit, offset, includeDisplay)
	}
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}

	// Convert service response to HTTP response
	httpAssignments := make([]AssignmentResponse, len(serviceResponse.Assignments))
	for i, sa := range serviceResponse.Assignments {
		httpAssignments[i] = AssignmentResponse(sa)
	}

	assignmentListResponse := &AssignmentListResponse{
		TotalResults: serviceResponse.TotalResults,
		StartIndex:   serviceResponse.StartIndex,
		Count:        serviceResponse.Count,
		Assignments:  httpAssignments,
		Links:        serviceResponse.Links,
	}

	sysutils.WriteSuccessResponse(ctx, w, http.StatusOK, assignmentListResponse)

	logger.Debug(ctx, "Successfully retrieved role assignments", log.String("role id", id),
		log.Int("limit", limit), log.Int("offset", offset),
		log.Bool("includeDisplay", includeDisplay),
		log.String("assigneeType", assigneeType),
		log.Int("totalResults", assignmentListResponse.TotalResults),
		log.Int("count", assignmentListResponse.Count))
}

// HandleRoleAddAssignmentsRequest handles the add assignments to role request.
func (rh *roleHandler) HandleRoleAddAssignmentsRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, handlerLoggerComponentName))

	id := r.PathValue("id")
	assignmentsRequest, err := sysutils.DecodeJSONBody[AssignmentsRequest](r)
	if err != nil {
		handleError(ctx, w, &ErrorInvalidRequestFormat)
		return
	}

	sanitizedRequest := rh.sanitizeAssignmentsRequest(assignmentsRequest)

	// Convert HTTP request to service request
	serviceRequest := rh.toRoleAssignments(sanitizedRequest)

	// Optional ouId: the sharee OU assigning its own principals. Empty means the role's owner.
	ouID := r.URL.Query().Get("ouId")

	svcErr := rh.assignmentService.AddAssignments(ctx, id, ouID, serviceRequest)
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}

	sysutils.WriteSuccessResponse(ctx, w, http.StatusNoContent, nil)
	logger.Debug(ctx, "Successfully added assignments to role", log.String("role id", id))
}

// HandleRoleRemoveAssignmentsRequest handles the remove assignments from role request.
func (rh *roleHandler) HandleRoleRemoveAssignmentsRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, handlerLoggerComponentName))

	id := r.PathValue("id")
	assignmentsRequest, err := sysutils.DecodeJSONBody[AssignmentsRequest](r)
	if err != nil {
		handleError(ctx, w, &ErrorInvalidRequestFormat)
		return
	}

	sanitizedRequest := rh.sanitizeAssignmentsRequest(assignmentsRequest)

	// Convert HTTP request to service request
	serviceRequest := rh.toRoleAssignments(sanitizedRequest)

	// Optional ouId: the sharee OU removing its own principals. Empty means the role's owner.
	ouID := r.URL.Query().Get("ouId")

	svcErr := rh.assignmentService.RemoveAssignments(ctx, id, ouID, serviceRequest)
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}

	sysutils.WriteSuccessResponse(ctx, w, http.StatusNoContent, nil)
	logger.Debug(ctx, "Successfully removed assignments from role", log.String("role id", id))
}

// HandleRoleGrantsPostRequest handles creating a grant on a role: the acting
// organization unit (req.InitiatingOUID, defaulting to the role's own owning OU) shares the role
// OU(s) per the request's target-scope fields. See ShareRequest for the two target-scope modes.
func (rh *roleHandler) HandleRoleGrantsPostRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, handlerLoggerComponentName))

	id := r.PathValue("id")
	req, err := sysutils.DecodeJSONBody[ShareRequest](r)
	if err != nil {
		handleError(ctx, w, &ErrorInvalidRequestFormat)
		return
	}

	role, svcErr := rh.roleService.GetRoleWithPermissions(ctx, id)
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}

	// A declaratively defined role can be granted through the API like any other: it is the grants
	// the file declares that are immutable, not the role's ability to gain further ones. A grant
	// created here is persisted, and the sharing service merges it with the declared ones.
	actingOUID := req.InitiatingOUID
	if actingOUID == "" {
		actingOUID = role.OUID
	}

	grants, svcErr := rh.sharingService.Share(
		ctx, roleSharingResourceType, id, role.OUID, actingOUID, req.ToSharePolicy())
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}

	sysutils.WriteSuccessResponse(
		ctx, w, http.StatusCreated, &GrantCreationResponse{Grants: toGrantResponses(grants)})
	logger.Debug(ctx, "Successfully shared role", log.String("role id", id))
}

// HandleRoleGrantsGetRequest lists a role's grants (admin/audit view), one page at a
// time. Grants declared in a role's declarative YAML are held in memory rather than persisted, and
// the sharing service merges them with the stored ones, so both are listed here.
func (rh *roleHandler) HandleRoleGrantsGetRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, handlerLoggerComponentName))

	id := r.PathValue("id")

	limit, offset, svcErr := parsePaginationParams(r.URL.Query())
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}
	if svcErr := validatePaginationParams(limit, offset); svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}

	page, svcErr := rh.sharingService.ListGrantsPage(ctx, roleSharingResourceType, id, limit, offset)
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}

	grants := toGrantResponses(page.Grants)
	response := &GrantListResponse{
		TotalResults: page.TotalResults,
		StartIndex:   offset + 1,
		Count:        len(grants),
		Grants:       grants,
		Links: sysutils.BuildPaginationLinks(
			fmt.Sprintf("/roles/%s/grants", id), limit, offset, page.TotalResults, ""),
	}

	sysutils.WriteSuccessResponse(ctx, w, http.StatusOK, response)
	logger.Debug(ctx, "Successfully listed role grants", log.String("role id", id),
		log.Int("limit", limit), log.Int("offset", offset),
		log.Int("totalResults", page.TotalResults), log.Int("count", response.Count))
}

// HandleRoleUnshareRequest revokes a grant.
func (rh *roleHandler) HandleRoleUnshareRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, handlerLoggerComponentName))

	grantID := r.PathValue("grantId")
	if svcErr := rh.sharingService.Unshare(ctx, grantID); svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}

	sysutils.WriteSuccessResponse(ctx, w, http.StatusNoContent, nil)
	logger.Debug(ctx, "Successfully unshared role grant", log.String("grantId", grantID))
}

// HandleRoleEditableFieldsGetRequest returns every templated field of the role currently editable
// by the acting organization unit (?ouId=, defaulting to the role's own owning organization unit).
func (rh *roleHandler) HandleRoleEditableFieldsGetRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	ouID := r.URL.Query().Get("ouId")

	fields, svcErr := rh.assignmentService.GetEditableFields(ctx, id, ouID)
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}

	sysutils.WriteSuccessResponse(ctx, w, http.StatusOK, &EditableFieldsResponse{Fields: fields})
}

// toGrantResponses converts service-layer grants to their HTTP response shape.
func toGrantResponses(grants []sharing.Grant) []GrantResponse {
	response := make([]GrantResponse, len(grants))
	for i, g := range grants {
		response[i] = GrantResponse{
			ID:             g.ID,
			Stage:          string(g.Stage),
			TargetScope:    string(g.TargetScope),
			TargetOUID:     g.TargetOUID,
			OwningOUID:     g.OwningOUID,
			ExcludedOUIDs:  g.ExcludedOUIDs,
			EditableFields: g.EditableFields,
		}
	}
	return response
}

// handleError handles service errors and returns appropriate HTTP responses.
func handleError(ctx context.Context, w http.ResponseWriter,
	svcErr *tidcommon.ServiceError) {
	statusCode := http.StatusInternalServerError
	if svcErr.Type == tidcommon.ClientErrorType {
		switch svcErr.Code {
		case ErrorRoleNotFound.Code, sharing.ErrorGrantNotFound.Code:
			statusCode = http.StatusNotFound
		case ErrorRoleNameConflict.Code:
			statusCode = http.StatusConflict
		case ErrorRoleNotSharedToOU.Code, ErrorAssignmentsNotEditable.Code, sharing.ErrorCoreConfigOwnerOnly.Code,
			ErrorRoleOutsideOwnOUScope.Code, ErrorRoleDeletionRestrictedToOwner.Code:
			statusCode = http.StatusForbidden
		case ErrorOrganizationUnitNotFound.Code,
			ErrorInvalidRequestFormat.Code, ErrorMissingRoleID.Code,
			ErrorInvalidLimit.Code, ErrorInvalidOffset.Code,
			ErrorEmptyAssignments.Code,
			ErrorInvalidAssignmentID.Code, ErrorMissingOUIDParam.Code:
			statusCode = http.StatusBadRequest
		case tidcommon.ErrorUnauthorized.Code, sysauthz.ErrorGrantNotPermitted.Code:
			statusCode = http.StatusForbidden
		default:
			statusCode = http.StatusBadRequest
		}
	}

	errResp := apierror.ErrorResponse{
		Code:        svcErr.Code,
		Message:     svcErr.Error,
		Description: svcErr.ErrorDescription,
	}

	sysutils.WriteErrorResponse(ctx, w, statusCode, errResp)
}

// sanitizeCreateRoleRequest sanitizes the create role request input.
func (rh *roleHandler) sanitizeCreateRoleRequest(request *CreateRoleRequest) CreateRoleRequest {
	sanitized := CreateRoleRequest{
		Name:        sysutils.SanitizeString(request.Name),
		Description: sysutils.SanitizeString(request.Description),
		OUID:        sysutils.SanitizeString(request.OUID),
	}

	if request.Permissions != nil {
		sanitized.Permissions = make([]ResourcePermissions, len(request.Permissions))
		for i, resPerm := range request.Permissions {
			sanitizedPerms := make([]string, len(resPerm.Permissions))
			for j, perm := range resPerm.Permissions {
				sanitizedPerms[j] = sysutils.SanitizeString(perm)
			}
			sanitized.Permissions[i] = ResourcePermissions{
				ResourceServerID: sysutils.SanitizeString(resPerm.ResourceServerID),
				Permissions:      sanitizedPerms,
			}
		}
	}

	if request.Assignments != nil {
		sanitized.Assignments = make([]AssignmentRequest, len(request.Assignments))
		for i, assignment := range request.Assignments {
			sanitized.Assignments[i] = AssignmentRequest{
				ID:   sysutils.SanitizeString(assignment.ID),
				Type: assignment.Type,
			}
		}
	}

	return sanitized
}

// sanitizeUpdateRoleRequest sanitizes the update role request input.
func (rh *roleHandler) sanitizeUpdateRoleRequest(request *UpdateRoleRequest) UpdateRoleRequest {
	sanitized := UpdateRoleRequest{
		Name:        sysutils.SanitizeString(request.Name),
		Description: sysutils.SanitizeString(request.Description),
		OUID:        sysutils.SanitizeString(request.OUID),
	}

	if request.Permissions != nil {
		sanitized.Permissions = make([]ResourcePermissions, len(request.Permissions))
		for i, resPerm := range request.Permissions {
			sanitizedPerms := make([]string, len(resPerm.Permissions))
			for j, perm := range resPerm.Permissions {
				sanitizedPerms[j] = sysutils.SanitizeString(perm)
			}
			sanitized.Permissions[i] = ResourcePermissions{
				ResourceServerID: sysutils.SanitizeString(resPerm.ResourceServerID),
				Permissions:      sanitizedPerms,
			}
		}
	}

	return sanitized
}

// sanitizeAssignmentsRequest sanitizes the assignments request input.
func (rh *roleHandler) sanitizeAssignmentsRequest(request *AssignmentsRequest) AssignmentsRequest {
	sanitized := AssignmentsRequest{}

	if request.Assignments != nil {
		sanitized.Assignments = make([]AssignmentRequest, len(request.Assignments))
		for i, assignment := range request.Assignments {
			sanitized.Assignments[i] = AssignmentRequest{
				ID:   sysutils.SanitizeString(assignment.ID),
				Type: assignment.Type,
			}
		}
	}

	return sanitized
}

// parsePaginationParams parses limit and offset query parameters from the request.
func parsePaginationParams(query url.Values) (int, int, *tidcommon.ServiceError) {
	limit := 0
	offset := 0

	if limitStr := query.Get("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err != nil {
			return 0, 0, &ErrorInvalidLimit
		} else {
			limit = parsedLimit
		}
	}

	if offsetStr := query.Get("offset"); offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err != nil {
			return 0, 0, &ErrorInvalidOffset
		} else {
			offset = parsedOffset
		}
	}

	if limit == 0 {
		limit = serverconst.DefaultPageSize
	}

	return limit, offset, nil
}

// toRoleCreationDetail converts HTTP CreateRoleRequest to service layer RoleCreationDetail.
func (rh *roleHandler) toRoleCreationDetail(req CreateRoleRequest) RoleCreationDetail {
	serviceAssignments := make([]RoleAssignment, len(req.Assignments))
	for i, a := range req.Assignments {
		serviceAssignments[i] = RoleAssignment{ID: a.ID, Type: a.Type}
	}

	return RoleCreationDetail{
		Name:        req.Name,
		Description: req.Description,
		OUID:        req.OUID,
		Permissions: req.Permissions,
		Assignments: serviceAssignments,
	}
}

// toHTTPRole converts service layer RoleWithPermissions to HTTP Role.
func (rh *roleHandler) toHTTPRoleResponse(role *RoleWithPermissions) *RoleResponse {
	r := RoleResponse(*role)
	return &r
}

// toHTTPCreateRoleResponse converts service layer RoleDetails to HTTP CreateRoleResponse.
func (rh *roleHandler) toHTTPCreateRoleResponse(role *RoleWithPermissionsAndAssignments) *CreateRoleResponse {
	httpAssignments := make([]AssignmentResponse, len(role.Assignments))
	for i, sa := range role.Assignments {
		httpAssignments[i] = AssignmentResponse{
			ID:   sa.ID,
			Type: sa.Type,
		}
	}
	permissions := role.Permissions
	if permissions == nil {
		permissions = make([]ResourcePermissions, 0)
	}

	return &CreateRoleResponse{
		ID:          role.ID,
		Name:        role.Name,
		Description: role.Description,
		OUID:        role.OUID,
		OUHandle:    role.OUHandle,
		Permissions: permissions,
		Assignments: httpAssignments,
	}
}

// toRoleAssignments converts HTTP AssignmentsRequest to service layer RoleAssignments.
func (rh *roleHandler) toRoleAssignments(req AssignmentsRequest) []RoleAssignment {
	serviceAssignments := make([]RoleAssignment, len(req.Assignments))
	for i, a := range req.Assignments {
		serviceAssignments[i] = RoleAssignment{ID: a.ID, Type: a.Type}
	}
	return serviceAssignments
}
