// Copyright 2025 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"github.com/thunder-id/thunderid/internal/sharing"
	"github.com/thunder-id/thunderid/internal/system/utils"
)

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
}

// AssignmentRequest represents an assignment of a role to a user or group.
type AssignmentRequest struct {
	ID   string       `json:"id"   native:"required"`
	Type AssigneeType `json:"type" native:"required,oneof=user app agent group"`
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
//
// OUID is the organization unit the assignment is recorded under (ROLE_ASSIGNMENT.ASSIGNING_OU_ID)
// — the role's own OU for assignments the owner made, or a sharee OU for assignments that OU made
// against a role shared to it. It is optional in declarative YAML: when omitted, the import and
// declarative-load paths resolve it to the assignee entity's own OU (see ResolveAssignmentOUIDs).
type RoleAssignment struct {
	ID   string       `yaml:"id"`
	Type AssigneeType `yaml:"type"`
	OUID string       `yaml:"ouId,omitempty"`
}

// RoleAssignmentWithDisplay represents an assignment used internally by the service layer.
type RoleAssignmentWithDisplay struct {
	ID      string
	Type    AssigneeType
	Display string
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

// Role origin values distinguishing whether a role returned for an OU is owned by that OU or
// was shared (directly or via reshare) to it. Core config (name, permissions) is always resolved
// from the owning OU regardless of origin — Role.OUID/OUHandle already reflect the owner.
const (
	RoleOriginOwned  = "owned"
	RoleOriginShared = "shared"
)

// RoleForOU represents a role visible to a given OU (owned or shared), with an explicit origin.
type RoleForOU struct {
	Role
	Origin string
}

// RoleListForOU represents the result of listing roles owned by or shared to an OU.
type RoleListForOU struct {
	TotalResults int
	StartIndex   int
	Count        int
	Roles        []RoleForOU
	Links        []utils.Link
}

// RoleSummaryForOUResponse represents a role visible to a given OU, over HTTP.
type RoleSummaryForOUResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	OUID        string `json:"ouId"`
	OUHandle    string `json:"ouHandle,omitempty"`
	IsReadOnly  bool   `json:"isReadOnly"`
	Origin      string `json:"origin"`
}

// RoleListForOUResponse represents the response for listing roles owned by or shared to an OU.
type RoleListForOUResponse struct {
	TotalResults int                        `json:"totalResults"`
	StartIndex   int                        `json:"startIndex"`
	Count        int                        `json:"count"`
	Roles        []RoleSummaryForOUResponse `json:"roles"`
	Links        []utils.Link               `json:"links"`
}

// ShareTarget names one organization unit to share to, and whether its own subtree comes with it.
// The named OU must be a direct child of the initiating OU either way; allChildren only decides how
// far below that child the grant reaches, which is never more than the child could have granted for
// itself.
type ShareTarget struct {
	// OUID is the organization unit being shared to.
	OUID string `json:"ouId" yaml:"ouId"`
	// AllChildren additionally shares to every OU in OUID's own subtree, at any depth, including
	// ones created later. Omit to share to OUID alone, leaving it to decide whether the resource
	// travels any further down.
	AllChildren bool `json:"allChildren,omitempty" yaml:"allChildren,omitempty"`
}

// ShareRequest represents the request body for creating a grant on a role. Exactly one of
// two target-scope modes must be selected: root-targeting (allRoots or rootOuIds — only valid when
// initiatingOuId is the role's own owning OU) or children-targeting (allChildren or ouIds — valid
// for any initiatingOuId currently visible for the role).
//
// This same shape is reused, unchanged, for a role's declarative YAML grants entries (see
// roleDeclarativeResource) and for POST /import's grants — both apply each entry via the
// identical Share() call the REST endpoint uses, so a hand-authored declarative grant, an exported
// grant, and a live API call are indistinguishable to the sharing framework. The yaml tags exist
// for those two paths; the json tags remain the REST contract.
type ShareRequest struct {
	// InitiatingOUID is the organization unit performing this share. Optional; defaults to the
	// role's own owning organization unit when omitted (the common case: the owner sharing for the
	// first time). Set explicitly when a different, already-visible organization unit is sharing
	// further within its own subtree. Named distinctly from the OUIDs targets below, which are the
	// organization units being shared *to*.
	InitiatingOUID string `json:"initiatingOuId,omitempty" yaml:"initiatingOuId,omitempty"`
	// AllOUs shares to every organization unit in the deployment at every depth, current and
	// future. Owner-only, and mutually exclusive with every other target-scope field. Unlike
	// AllRoots this reaches descendants too. Reserved for a resource the whole deployment must
	// always see; ordinary distribution should name its recipients.
	AllOUs    bool     `json:"allOus,omitempty"    yaml:"allOus,omitempty"`
	AllRoots  bool     `json:"allRoots,omitempty"  yaml:"allRoots,omitempty"`
	RootOUIDs []string `json:"rootOuIds,omitempty" yaml:"rootOuIds,omitempty"`
	// ExcludedRootOUIDs carves these Root OUs (and their subtrees) out of an AllRoots share.
	// Ignored unless AllRoots is true.
	ExcludedRootOUIDs []string `json:"excludedRootOuIds,omitempty" yaml:"excludedRootOuIds,omitempty"`
	AllChildren       bool     `json:"allChildren,omitempty"       yaml:"allChildren,omitempty"`
	// OUIDs names the organization units to share to explicitly, each of which must be a direct
	// child of InitiatingOUID — reaching a grandchild selectively requires that child to issue its
	// own share call in turn. Each entry decides for itself, via ShareTarget.AllChildren, whether
	// that child's own subtree comes with it. Ignored when AllChildren is true.
	OUIDs []ShareTarget `json:"ouIds,omitempty" yaml:"ouIds,omitempty"`
	// ExcludedOUIDs carves these OUs (and their subtrees) out of an AllChildren share, out of an
	// AllOUs share, or out of any OUIDs entry whose own subtree contains them. Ignored when none of
	// those applies.
	ExcludedOUIDs []string `json:"excludedOuIds,omitempty" yaml:"excludedOuIds,omitempty"`
	// EditableFields names the templated fields ("assignments", "assignments.user",
	// "assignments.group", "assignments.app", "assignments.agent") made editable through this
	// grant. Omit for "everything": every field, when ouId is the role's own owning organization
	// unit; exactly ouId's own current editable set, when ouId is a sharee reshare — a reshare may
	// only narrow this set relative to its own, never widen it.
	EditableFields []string `json:"editableFields,omitempty" yaml:"editableFields,omitempty"`
}

// ToSharePolicy converts req's target-scope fields into the sharing.SharePolicy Share() expects.
// InitiatingOUID is not part of SharePolicy — it selects the acting OU, resolved by the caller.
//
// The one non-mechanical step is OUIDs: the API groups every explicit target into one list and
// lets each entry say whether its subtree comes too, while SharePolicy keeps the two apart,
// because they are two distinct target scopes (ou and ou_subtree) once stored.
func (req ShareRequest) ToSharePolicy() sharing.SharePolicy {
	policy := sharing.SharePolicy{
		AllOUs:            req.AllOUs,
		AllRoots:          req.AllRoots,
		RootOUIDs:         req.RootOUIDs,
		ExcludedRootOUIDs: req.ExcludedRootOUIDs,
		AllChildren:       req.AllChildren,
		ExcludedOUIDs:     req.ExcludedOUIDs,
		EditableFields:    req.EditableFields,
	}
	for _, target := range req.OUIDs {
		if target.AllChildren {
			policy.SubtreeOUIDs = append(policy.SubtreeOUIDs, target.OUID)
			continue
		}
		policy.OUIDs = append(policy.OUIDs, target.OUID)
	}
	return policy
}

// shareRequestFromReplayableGrant converts one sharing.ReplayableGrant (see
// sharing.ServiceInterface.ExportGrants) back into the ShareRequest shape used for declarative
// YAML and POST /import — the inverse of ToSharePolicy, with ActingOUID carried as InitiatingOUID
// and the policy's two explicit-target lists merged back into one.
func shareRequestFromReplayableGrant(g sharing.ReplayableGrant) ShareRequest {
	req := ShareRequest{
		InitiatingOUID:    g.ActingOUID,
		AllOUs:            g.Policy.AllOUs,
		AllRoots:          g.Policy.AllRoots,
		RootOUIDs:         g.Policy.RootOUIDs,
		ExcludedRootOUIDs: g.Policy.ExcludedRootOUIDs,
		AllChildren:       g.Policy.AllChildren,
		ExcludedOUIDs:     g.Policy.ExcludedOUIDs,
		EditableFields:    g.Policy.EditableFields,
	}
	for _, ouID := range g.Policy.OUIDs {
		req.OUIDs = append(req.OUIDs, ShareTarget{OUID: ouID})
	}
	for _, ouID := range g.Policy.SubtreeOUIDs {
		req.OUIDs = append(req.OUIDs, ShareTarget{OUID: ouID, AllChildren: true})
	}
	return req
}

// GrantResponse represents a single grant over HTTP.
type GrantResponse struct {
	ID          string `json:"id"`
	Stage       string `json:"stage"`
	TargetScope string `json:"targetScope"`
	TargetOUID  string `json:"targetOuId,omitempty"`
	OwningOUID  string `json:"owningOuId"`
	// ExcludedOUIDs is only ever non-empty for the target scopes that carry a subtree with them:
	// all_roots, all_children and ou_subtree. A plain ou grant reaches one OU and no further, so
	// there is nothing under it to carve out.
	ExcludedOUIDs []string `json:"excludedOuIds,omitempty"`
	// EditableFields is the materialized set of templated fields editable through this grant.
	EditableFields []string `json:"editableFields,omitempty"`
}

// GrantCreationResponse represents the response for creating grants on a role. It
// carries every grant the call created (a root-targeting share can fan out to several roots), so
// it is a creation result rather than a page of an existing list and is deliberately not paginated.
type GrantCreationResponse struct {
	Grants []GrantResponse `json:"grants"`
}

// GrantListResponse represents the paginated response for listing a role's grants.
type GrantListResponse struct {
	TotalResults int             `json:"totalResults"`
	StartIndex   int             `json:"startIndex"`
	Count        int             `json:"count"`
	Grants       []GrantResponse `json:"grants"`
	Links        []utils.Link    `json:"links"`
}

// EditableFieldsResponse represents the response for the "which templated fields can this
// organization unit edit" metadata endpoint.
type EditableFieldsResponse struct {
	Fields []string `json:"fields"`
}

// AssignmentList represents the result of listing role assignments.
type AssignmentList struct {
	TotalResults int
	StartIndex   int
	Count        int
	Assignments  []RoleAssignmentWithDisplay
	Links        []utils.Link
}
