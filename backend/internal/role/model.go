// Copyright 2025 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import "github.com/thunder-id/thunderid/internal/system/utils"

// AssigneeType represents the type of assignee principal.
type AssigneeType string

// Public assignee types accepted in requests and returned in responses.
const (
	// AssigneeTypeUser is the public type for user principals.
	AssigneeTypeUser AssigneeType = "user"
	// AssigneeTypeApp is the public type for application principals.
	AssigneeTypeApp AssigneeType = "app"
	// AssigneeTypeAgent is the public type for agent principals.
	AssigneeTypeAgent AssigneeType = "agent"
	// AssigneeTypeGroup is the public type for group principals.
	AssigneeTypeGroup AssigneeType = "group"
)

// Internal assignee types used only for storage.
const (
	assigneeTypeEntity AssigneeType = "entity"
)

// IsEntityType reports whether t is an entity type (user, app, agent) that maps
// to the internal entity storage type.
func (t AssigneeType) IsEntityType() bool {
	switch t {
	case AssigneeTypeUser, AssigneeTypeApp, AssigneeTypeAgent:
		return true
	}
	return false
}

// AssignmentResponse represents an assignment of a role to a user or group.
type AssignmentResponse struct {
	ID      string       `json:"id"`
	Type    AssigneeType `json:"type"`
	Display string       `json:"display,omitempty"`
	// OUID is the organization unit the assignment is made in.
	OUID string `json:"ouId,omitempty"`
}

// AssignmentRequest represents an assignment of a role to a user or group.
type AssignmentRequest struct {
	ID   string       `json:"id"   native:"required"`
	Type AssigneeType `json:"type" native:"required,oneof=user app agent group"`
	// OUID is the organization unit the assignment is made in. Left out, it is the assignee's own.
	OUID string `json:"ouId,omitempty"`
}

// RoleSummaryResponse represents the basic information of a role.
type RoleSummaryResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	OUID        string `json:"ouId"`
	OUHandle    string `json:"ouHandle,omitempty"`
	IsReadOnly  bool   `json:"isReadOnly"`
}

// RoleResponse represents a complete role with permissions.
type RoleResponse struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	Description string                `json:"description,omitempty"`
	OUID        string                `json:"ouId"`
	OUHandle    string                `json:"ouHandle,omitempty"`
	Permissions []ResourcePermissions `json:"permissions"`
}

// CreateRoleRequest represents the request body for creating a role.
type CreateRoleRequest struct {
	Name        string                `json:"name"                  native:"required,min=1,max=100"`
	Description string                `json:"description,omitempty"`
	OUID        string                `json:"ouId"                  native:"required"`
	Permissions []ResourcePermissions `json:"permissions"`
	Assignments []AssignmentRequest   `json:"assignments,omitempty"`
}

// CreateRoleResponse represents the response body for creating a role.
type CreateRoleResponse struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	Description string                `json:"description,omitempty"`
	OUID        string                `json:"ouId"`
	OUHandle    string                `json:"ouHandle,omitempty"`
	Permissions []ResourcePermissions `json:"permissions"`
	Assignments []AssignmentResponse  `json:"assignments,omitempty"`
}

// UpdateRoleRequest represents the request body for updating a role.
type UpdateRoleRequest struct {
	Name        string                `json:"name"                  native:"required,min=1,max=100"`
	Description string                `json:"description,omitempty"`
	OUID        string                `json:"ouId"                  native:"required"`
	Permissions []ResourcePermissions `json:"permissions"`
}

// AssignmentsRequest represents the request body for adding or removing assignments.
type AssignmentsRequest struct {
	Assignments []AssignmentRequest `json:"assignments" native:"required,min=1,dive"`
}

// RoleListResponse represents the response for listing roles with pagination.
type RoleListResponse struct {
	TotalResults int                   `json:"totalResults"`
	StartIndex   int                   `json:"startIndex"`
	Count        int                   `json:"count"`
	Roles        []RoleSummaryResponse `json:"roles"`
	Links        []utils.Link          `json:"links"`
}

// AssignmentListResponse represents the response for listing role assignments with pagination.
type AssignmentListResponse struct {
	TotalResults int                  `json:"totalResults"`
	StartIndex   int                  `json:"startIndex"`
	Count        int                  `json:"count"`
	Assignments  []AssignmentResponse `json:"assignments"`
	Links        []utils.Link         `json:"links"`
}

// Internal service layer structs - used for business logic processing

// ResourcePermissions represents permissions grouped by resource server.
type ResourcePermissions struct {
	ResourceServerID string   `json:"resourceServerId" yaml:"resourceServerId"`
	Permissions      []string `json:"permissions"      yaml:"permissions"`
}

// RoleCreationDetail represents the parameters for creating a role.
// ID is optional; if empty, the service generates a new UUID.
type RoleCreationDetail struct {
	ID          string
	Name        string
	Description string
	OUID        string
	Permissions []ResourcePermissions
	Assignments []RoleAssignment
}

// RoleWithPermissionsAndAssignments represents the parameters for creating a role.
type RoleWithPermissionsAndAssignments struct {
	ID          string
	Name        string
	Description string
	OUID        string
	OUHandle    string
	Permissions []ResourcePermissions
	Assignments []RoleAssignment
}

// RoleAssignment represents an assignment used internally by the service layer.
type RoleAssignment struct {
	ID   string       `yaml:"id"`
	Type AssigneeType `yaml:"type"`
	OUID string `yaml:"ouId,omitempty"`
}

// RoleAssignmentWithDisplay represents an assignment used internally by the service layer.
type RoleAssignmentWithDisplay struct {
	ID      string
	Type    AssigneeType
	Display string
	OUID    string
}

// Role represents basic role information used internally by the service layer.
type Role struct {
	ID          string
	Name        string
	Description string
	OUID        string
	OUHandle    string
	IsReadOnly  bool
}

// RoleWithPermissions represents complete role details used internally by the service layer.
type RoleWithPermissions struct {
	ID          string
	Name        string
	Description string
	OUID        string
	OUHandle    string
	Permissions []ResourcePermissions
}

// RoleUpdateDetail represents the parameters for creating a role.
type RoleUpdateDetail struct {
	Name        string
	Description string
	OUID        string
	Permissions []ResourcePermissions
}

// RoleList represents the result of listing roles.
type RoleList struct {
	TotalResults int
	StartIndex   int
	Count        int
	Roles        []Role
	Links        []utils.Link
}

// AssignmentList represents the result of listing role assignments.
type AssignmentList struct {
	TotalResults int
	StartIndex   int
	Count        int
	Assignments  []RoleAssignmentWithDisplay
	Links        []utils.Link
}

// SharingPolicyRequest is a sharing policy as this API creates one, which is narrower than what
// the framework can hold. It carries no policy id: the id is the framework's to mint on an
// interactive create. Declaring it here would accept bodies the published schema refuses.
type SharingPolicyRequest struct {
	InitiatingOUID string `json:"initiatingOuId,omitempty"`
	SharingPolicyUpdateRequest
}

// SharingPolicyUpdateRequest is an edit of a sharing policy: its sections and the version being
// edited. Whose decision the policy is cannot change, since that would be another policy, so an
// edit does not carry it.
type SharingPolicyUpdateRequest struct {
	AllUnits       *SharingAllUnitsRequest       `json:"allUnits,omitempty"`
	ChildUnits     *SharingChildUnitsRequest     `json:"childUnits,omitempty"`
	OtherTreeRoots *SharingOtherTreeRootsRequest `json:"otherTreeRoots,omitempty"`
	Version        int                           `json:"version,omitempty"`
}

// SharingOverlayRuleRequest is a term on one assignment field: whether a reached organization unit
// may assign the role to that type of assignee. A role rule states nothing else.
type SharingOverlayRuleRequest struct {
	Editable bool `json:"editable"`
}

// SharingAllUnitsRequest is the section reaching every organization unit. A create may not state
// it; an edit restates it to rewrite the exclusions or terms of a policy that already holds it.
type SharingAllUnitsRequest struct {
	ExcludedOUIDs []string                             `json:"excludedOuIds,omitempty"`
	OverlayRules  map[string]SharingOverlayRuleRequest `json:"overlayRules,omitempty"`
}

// SharingChildUnitsRequest is the section about the organization units beneath the issuer, with
// the fields the schema lists.
type SharingChildUnitsRequest struct {
	Mode          string                               `json:"mode"`
	ExcludedOUIDs []string                             `json:"excludedOuIds,omitempty"`
	OverlayRules  map[string]SharingOverlayRuleRequest `json:"overlayRules,omitempty"`
	Units         []SharingChildUnitRequest            `json:"units,omitempty"`
}

// SharingChildUnitRequest names one direct child of the issuer, how far the role carries from it,
// and the terms it holds the role on.
type SharingChildUnitRequest struct {
	OUID         string                               `json:"ouId"`
	Reach        string                               `json:"reach"`
	OverlayRules map[string]SharingOverlayRuleRequest `json:"overlayRules,omitempty"`
}

// SharingOtherTreeRootsRequest is the section about the root organization units of other trees,
// with the fields the schema lists.
type SharingOtherTreeRootsRequest struct {
	Mode          string                               `json:"mode"`
	ExcludedOUIDs []string                             `json:"excludedOuIds,omitempty"`
	OverlayRules  map[string]SharingOverlayRuleRequest `json:"overlayRules,omitempty"`
	Units         []SharingRootUnitRequest             `json:"units,omitempty"`
}

// SharingRootUnitRequest names the root organization unit of one other tree and the terms it holds
// the role on.
type SharingRootUnitRequest struct {
	OUID         string                               `json:"ouId"`
	OverlayRules map[string]SharingOverlayRuleRequest `json:"overlayRules,omitempty"`
}
