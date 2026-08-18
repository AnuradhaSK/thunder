// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"context"
	"testing"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"

	"github.com/thunder-id/thunderid/internal/sharing"
	serverconst "github.com/thunder-id/thunderid/internal/system/constants"
	declarativeresource "github.com/thunder-id/thunderid/internal/system/declarative_resource"
	"github.com/thunder-id/thunderid/internal/system/log"
)

// RoleExporterTestSuite contains tests for the roleExporter.
type RoleExporterTestSuite struct {
	suite.Suite
	mockService           *RoleServiceInterfaceMock
	mockAssignmentService *RoleAssignmentServiceInterfaceMock
	sharingService        *fakeSharingService
	exporter              declarativeresource.ResourceExporter
	ctx                   context.Context
}

func TestRoleExporterTestSuite(t *testing.T) {
	suite.Run(t, new(RoleExporterTestSuite))
}

func (suite *RoleExporterTestSuite) SetupTest() {
	suite.mockService = NewRoleServiceInterfaceMock(suite.T())
	suite.mockAssignmentService = NewRoleAssignmentServiceInterfaceMock(suite.T())
	suite.sharingService = &fakeSharingService{}
	suite.exporter = newRoleExporter(suite.mockService, suite.mockAssignmentService, suite.sharingService)
	suite.ctx = context.Background()
}

// Test GetResourceType
func (suite *RoleExporterTestSuite) TestGetResourceType() {
	assert.Equal(suite.T(), resourceTypeRole, suite.exporter.GetResourceType())
}

// Test GetParameterizerType
func (suite *RoleExporterTestSuite) TestGetParameterizerType() {
	assert.Equal(suite.T(), paramTypeRole, suite.exporter.GetParameterizerType())
}

// Test GetResourceRules
func (suite *RoleExporterTestSuite) TestGetResourceRules() {
	rules := suite.exporter.GetResourceRules()
	assert.NotNil(suite.T(), rules)
	assert.Empty(suite.T(), rules.Variables)
	assert.Empty(suite.T(), rules.ArrayVariables)
}

// Test GetAllResourceIDs - single page
func (suite *RoleExporterTestSuite) TestGetAllResourceIDs_SinglePage() {
	roleList := &RoleList{
		Roles: []Role{
			{ID: "role1", Name: "Admin", OUID: "ou1"},
			{ID: "role2", Name: "Viewer", OUID: "ou1"},
		},
		TotalResults: 2,
	}

	suite.mockService.On("GetRoleList", suite.ctx, serverconst.MaxPageSize, 0).Return(
		roleList, nil,
	)
	suite.mockService.On("GetRoleList", suite.ctx, serverconst.MaxPageSize, 2).Return(
		&RoleList{Roles: []Role{}, TotalResults: 2}, nil,
	)
	suite.mockService.On("IsRoleDeclarative", suite.ctx, "role1").Return(false, nil)
	suite.mockService.On("IsRoleDeclarative", suite.ctx, "role2").Return(false, nil)

	ids, err := suite.exporter.GetAllResourceIDs(suite.ctx)

	suite.Nil(err)
	assert.Len(suite.T(), ids, 2)
	assert.Contains(suite.T(), ids, "role1")
	assert.Contains(suite.T(), ids, "role2")
	suite.mockService.AssertExpectations(suite.T())
}

// Test GetAllResourceIDs - multiple pages
func (suite *RoleExporterTestSuite) TestGetAllResourceIDs_MultiplePages() {
	page1 := &RoleList{
		Roles: []Role{
			{ID: "role1", Name: "Admin", OUID: "ou1"},
		},
		TotalResults: 2,
	}
	page2 := &RoleList{
		Roles: []Role{
			{ID: "role2", Name: "Viewer", OUID: "ou1"},
		},
		TotalResults: 2,
	}
	emptyPage := &RoleList{
		Roles:        []Role{},
		TotalResults: 2,
	}

	suite.mockService.On("GetRoleList", suite.ctx, serverconst.MaxPageSize, 0).Return(page1, nil)
	suite.mockService.On("GetRoleList", suite.ctx, serverconst.MaxPageSize, 1).Return(page2, nil)
	suite.mockService.On("GetRoleList", suite.ctx, serverconst.MaxPageSize, 2).Return(emptyPage, nil)
	suite.mockService.On("IsRoleDeclarative", suite.ctx, "role1").Return(false, nil)
	suite.mockService.On("IsRoleDeclarative", suite.ctx, "role2").Return(false, nil)

	ids, err := suite.exporter.GetAllResourceIDs(suite.ctx)

	suite.Nil(err)
	assert.Len(suite.T(), ids, 2)
	suite.mockService.AssertExpectations(suite.T())
}

// Test GetAllResourceIDs - excludes declarative roles
func (suite *RoleExporterTestSuite) TestGetAllResourceIDs_ExcludesDeclarativeRoles() {
	roleList := &RoleList{
		Roles: []Role{
			{ID: "role1", Name: "Admin", OUID: "ou1"},
			{ID: "role-declarative", Name: "Declarative Role", OUID: "ou1"},
		},
		TotalResults: 2,
	}

	suite.mockService.On("GetRoleList", suite.ctx, serverconst.MaxPageSize, 0).Return(
		roleList, nil,
	)
	suite.mockService.On("GetRoleList", suite.ctx, serverconst.MaxPageSize, 2).Return(
		&RoleList{Roles: []Role{}, TotalResults: 2}, nil,
	)
	suite.mockService.On("IsRoleDeclarative", suite.ctx, "role1").Return(false, nil)
	suite.mockService.On("IsRoleDeclarative", suite.ctx, "role-declarative").Return(
		true, nil,
	)

	ids, err := suite.exporter.GetAllResourceIDs(suite.ctx)

	suite.Nil(err)
	assert.Len(suite.T(), ids, 1)
	assert.Equal(suite.T(), "role1", ids[0])
	suite.mockService.AssertExpectations(suite.T())
}

// Test GetAllResourceIDs - error on GetRoleList
func (suite *RoleExporterTestSuite) TestGetAllResourceIDs_ErrorOnGetRoleList() {
	serviceErr := &tidcommon.ServiceError{Code: "500"}
	suite.mockService.On("GetRoleList", suite.ctx, serverconst.MaxPageSize, 0).Return(nil, serviceErr)

	ids, err := suite.exporter.GetAllResourceIDs(suite.ctx)

	suite.NotNil(err)
	assert.Nil(suite.T(), ids)
	assert.Equal(suite.T(), serviceErr, err)
}

// Test GetAllResourceIDs - error on IsRoleDeclarative
func (suite *RoleExporterTestSuite) TestGetAllResourceIDs_ErrorOnIsRoleDeclarative() {
	roleList := &RoleList{
		Roles: []Role{
			{ID: "role1", Name: "Admin", OUID: "ou1"},
		},
		TotalResults: 1,
	}
	serviceErr := &tidcommon.ServiceError{Code: "500"}

	suite.mockService.On("GetRoleList", suite.ctx, serverconst.MaxPageSize, 0).Return(roleList, nil)
	suite.mockService.On("IsRoleDeclarative", suite.ctx, "role1").Return(false, serviceErr)

	ids, err := suite.exporter.GetAllResourceIDs(suite.ctx)

	suite.NotNil(err)
	assert.Nil(suite.T(), ids)
	assert.Equal(suite.T(), serviceErr, err)
}

// Test GetResourceByID - success
func (suite *RoleExporterTestSuite) TestGetResourceByID_Success() {
	roleWithPerms := &RoleWithPermissions{
		ID:          "role1",
		Name:        "Admin",
		Description: "Admin role",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{
			{ResourceServerID: "rs1", Permissions: []string{"read", "write"}},
		},
	}

	suite.mockService.On("GetRoleWithPermissions", suite.ctx, "role1").Return(
		roleWithPerms, nil,
	)
	suite.mockAssignmentService.On(
		"GetRoleAssignments", suite.ctx, "role1", "ou1", serverconst.MaxPageSize, 0, false,
	).Return(&AssignmentList{
		Assignments: []RoleAssignmentWithDisplay{
			{ID: "user1", Type: assigneeTypeEntity},
			{ID: "group1", Type: AssigneeTypeGroup},
		},
		TotalResults: 2,
	}, nil)
	suite.mockAssignmentService.On(
		"GetRoleAssignments", suite.ctx, "role1", "ou1", serverconst.MaxPageSize, 2, false,
	).Return(&AssignmentList{
		Assignments:  []RoleAssignmentWithDisplay{},
		TotalResults: 2,
	}, nil)
	suite.mockAssignmentService.On("GetAssigningOUIDs", suite.ctx, "role1").Return([]string{"ou1"}, nil)
	suite.sharingService.exportGrantsFunc = func(
		_ context.Context, _ sharing.ResourceType, _ string,
	) ([]sharing.ReplayableGrant, *tidcommon.ServiceError) {
		return nil, nil
	}

	resource, name, err := suite.exporter.GetResourceByID(suite.ctx, "role1")

	suite.Nil(err)
	assert.Equal(suite.T(), "Admin", name)
	assert.NotNil(suite.T(), resource)

	role, ok := resource.(*roleDeclarativeResource)
	assert.True(suite.T(), ok)
	assert.Equal(suite.T(), "role1", role.ID)
	assert.Equal(suite.T(), []RoleAssignment{
		{ID: "user1", Type: assigneeTypeEntity, OUID: "ou1"},
		{ID: "group1", Type: AssigneeTypeGroup, OUID: "ou1"},
	}, role.Assignments)
	assert.Empty(suite.T(), role.Grants)
}

// Test GetResourceByID - includes a sharee OU's assignments and a grant
func (suite *RoleExporterTestSuite) TestGetResourceByID_IncludesShareeOUAssignmentsAndGrants() {
	roleWithPerms := &RoleWithPermissions{
		ID:   "role1",
		Name: "Admin",
		OUID: "ou1",
	}

	suite.mockService.On("GetRoleWithPermissions", suite.ctx, "role1").Return(roleWithPerms, nil)
	suite.mockAssignmentService.On(
		"GetRoleAssignments", suite.ctx, "role1", "ou1", serverconst.MaxPageSize, 0, false,
	).Return(&AssignmentList{Assignments: []RoleAssignmentWithDisplay{}, TotalResults: 0}, nil)
	suite.mockAssignmentService.On("GetAssigningOUIDs", suite.ctx, "role1").Return([]string{"ou1", "ou2"}, nil)
	suite.mockAssignmentService.On(
		"GetRoleAssignments", suite.ctx, "role1", "ou2", serverconst.MaxPageSize, 0, false,
	).Return(&AssignmentList{
		Assignments:  []RoleAssignmentWithDisplay{{ID: "user2", Type: assigneeTypeEntity}},
		TotalResults: 1,
	}, nil)
	suite.mockAssignmentService.On(
		"GetRoleAssignments", suite.ctx, "role1", "ou2", serverconst.MaxPageSize, 1, false,
	).Return(&AssignmentList{Assignments: []RoleAssignmentWithDisplay{}, TotalResults: 1}, nil)
	suite.sharingService.exportGrantsFunc = func(
		_ context.Context, _ sharing.ResourceType, _ string,
	) ([]sharing.ReplayableGrant, *tidcommon.ServiceError) {
		return []sharing.ReplayableGrant{
			{ActingOUID: "ou1", Policy: sharing.SharePolicy{OUIDs: []string{"ou2"}}},
		}, nil
	}

	resource, _, err := suite.exporter.GetResourceByID(suite.ctx, "role1")

	suite.Nil(err)
	role, ok := resource.(*roleDeclarativeResource)
	suite.Require().True(ok)
	// The sharee OU's assignment is exported in the one flat list, stamped with the OU that made it.
	suite.Equal([]RoleAssignment{{ID: "user2", Type: assigneeTypeEntity, OUID: "ou2"}}, role.Assignments)
	suite.Equal([]ShareRequest{{InitiatingOUID: "ou1", OUIDs: []ShareTarget{{OUID: "ou2"}}}}, role.Grants)
}

// Test GetResourceByID - error on GetRoleWithPermissions
func (suite *RoleExporterTestSuite) TestGetResourceByID_ErrorOnGetRoleWithPermissions() {
	serviceErr := &tidcommon.ServiceError{Code: "404"}
	suite.mockService.On("GetRoleWithPermissions", suite.ctx, "nonexistent").Return(nil, serviceErr)

	resource, name, err := suite.exporter.GetResourceByID(suite.ctx, "nonexistent")

	suite.NotNil(err)
	assert.Nil(suite.T(), resource)
	assert.Empty(suite.T(), name)
	assert.Equal(suite.T(), serviceErr, err)
}

// Test ValidateResource - success
func (suite *RoleExporterTestSuite) TestValidateResource_Success() {
	resource := &roleDeclarativeResource{
		ID:   "role1",
		Name: "Admin",
		OUID: "ou1",
	}
	logger := log.GetLogger()

	name, exportErr := suite.exporter.ValidateResource(context.Background(), resource, "role1", logger)

	suite.Nil(exportErr)
	assert.Equal(suite.T(), "Admin", name)
}

// Test ValidateResource - invalid type
func (suite *RoleExporterTestSuite) TestValidateResource_InvalidType() {
	logger := log.GetLogger()

	name, exportErr := suite.exporter.ValidateResource(context.Background(), "not a role", "role1", logger)

	suite.NotNil(exportErr)
	assert.Empty(suite.T(), name)
}

// Test parseToRole - valid YAML
func (suite *RoleExporterTestSuite) TestParseToRole_ValidYAML() {
	yamlData := []byte(`
id: role1
name: Admin
description: Admin role
ouId: ou1
permissions:
  - resourceServerId: rs1
    permissions:
      - read
      - write
assignments:
  - id: user1
    type: user
`)

	role, err := parseToRole(yamlData)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), role)
	assert.Equal(suite.T(), "role1", role.ID)
	assert.Equal(suite.T(), "Admin", role.Name)
	assert.Equal(suite.T(), "Admin role", role.Description)
	assert.Equal(suite.T(), "ou1", role.OUID)
	assert.Len(suite.T(), role.Permissions, 1)
	assert.Len(suite.T(), role.Assignments, 1)
}

// Test parseToRole - invalid YAML
func (suite *RoleExporterTestSuite) TestParseToRole_InvalidYAML() {
	yamlData := []byte(`
invalid: yaml: content:
`)

	role, err := parseToRole(yamlData)

	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), role)
}

// Test parseToRole - optional fields omitted
func (suite *RoleExporterTestSuite) TestParseToRole_OptionalFieldsOmitted() {
	yamlData := []byte(`
id: role1
name: Admin
ouId: ou1
`)

	role, err := parseToRole(yamlData)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), role)
	assert.Empty(suite.T(), role.Description)
	assert.Empty(suite.T(), role.Assignments)
	assert.Empty(suite.T(), role.Permissions)
}

// Test validateRoleWrapper - valid role
func (suite *RoleExporterTestSuite) TestValidateRoleWrapper_ValidRole() {
	role := &RoleWithPermissionsAndAssignments{
		ID:   "role1",
		Name: "Admin",
		OUID: "ou1",
		Permissions: []ResourcePermissions{
			{ResourceServerID: "rs1", Permissions: []string{"read"}},
		},
		Assignments: []RoleAssignment{
			{ID: "user1", Type: assigneeTypeEntity},
		},
	}

	// Pass nil for fileStore to skip duplicate check (for unit test purposes)
	err := validateRoleWrapper(role, nil, nil, nil)

	assert.NoError(suite.T(), err)
}

// Test validateRoleWrapper - missing ID
func (suite *RoleExporterTestSuite) TestValidateRoleWrapper_MissingID() {
	role := &RoleWithPermissionsAndAssignments{
		Name: "Admin",
		OUID: "ou1",
	}

	err := validateRoleWrapper(role, nil, nil, nil)

	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "role ID is required")
}

// Test validateRoleWrapper - missing name
func (suite *RoleExporterTestSuite) TestValidateRoleWrapper_MissingName() {
	role := &RoleWithPermissionsAndAssignments{
		ID:   "role1",
		OUID: "ou1",
	}

	err := validateRoleWrapper(role, nil, nil, nil)

	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "role name is required")
}

// Test validateRoleWrapper - missing organization unit ID
func (suite *RoleExporterTestSuite) TestValidateRoleWrapper_MissingOUID() {
	role := &RoleWithPermissionsAndAssignments{
		ID:   "role1",
		Name: "Admin",
	}

	err := validateRoleWrapper(role, nil, nil, nil)

	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "ouId or ouHandle is required for role 'Admin'")
}

// Test validateRoleWrapper - invalid assignment type
func (suite *RoleExporterTestSuite) TestValidateRoleWrapper_InvalidAssignmentType() {
	role := &RoleWithPermissionsAndAssignments{
		ID:   "role1",
		Name: "Admin",
		OUID: "ou1",
		Assignments: []RoleAssignment{
			{ID: "user1", Type: "invalid"},
		},
	}

	err := validateRoleWrapper(role, nil, nil, nil)

	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "invalid assignment type")
}

// Test validateRoleWrapper - missing assignment ID
func (suite *RoleExporterTestSuite) TestValidateRoleWrapper_MissingAssignmentID() {
	role := &RoleWithPermissionsAndAssignments{
		ID:   "role1",
		Name: "Admin",
		OUID: "ou1",
		Assignments: []RoleAssignment{
			{Type: assigneeTypeEntity},
		},
	}

	err := validateRoleWrapper(role, nil, nil, nil)

	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "assignment ID is required")
}

// Test validateRoleWrapper - missing resource server ID
func (suite *RoleExporterTestSuite) TestValidateRoleWrapper_MissingResourceServerID() {
	role := &RoleWithPermissionsAndAssignments{
		ID:   "role1",
		Name: "Admin",
		OUID: "ou1",
		Permissions: []ResourcePermissions{
			{Permissions: []string{"read"}},
		},
	}

	err := validateRoleWrapper(role, nil, nil, nil)

	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "resource server ID is required")
}

// Test toResourcePermissions
func (suite *RoleExporterTestSuite) TestToResourcePermissions() {
	perm := roleDeclarativePermission{
		ResourceServerID: "rs1",
		Permissions:      []string{"read", "write"},
	}

	result := toResourcePermissions(perm)

	assert.Equal(suite.T(), "rs1", result.ResourceServerID)
	assert.Len(suite.T(), result.Permissions, 2)
	assert.Contains(suite.T(), result.Permissions, "read")
	assert.Contains(suite.T(), result.Permissions, "write")
}

// Test that roleDeclarativeResource's grants and per-assignment ouId YAML tags round-trip.
func (suite *RoleExporterTestSuite) TestRoleDeclarativeResource_ParsesGrantsAndAssignmentOUIDs() {
	yamlData := []byte(`
id: role1
name: Admin
ouId: ou1
permissions: []
grants:
  - initiatingOuId: ou1
    allChildren: true
    excludedOuIds: [ou1-a]
    editableFields: [assignments.group]
assignments:
  - id: user1
    type: user
  - id: user2
    type: user
    ouId: ou2
`)

	var resource roleDeclarativeResource
	err := yaml.Unmarshal(yamlData, &resource)
	suite.NoError(err)

	suite.Equal([]ShareRequest{
		{
			InitiatingOUID: "ou1",
			AllChildren:    true,
			ExcludedOUIDs:  []string{"ou1-a"},
			EditableFields: []string{"assignments.group"},
		},
	}, resource.Grants)
	// An omitted ouId stays empty at parse time; it is resolved to the assignee's own OU later.
	suite.Equal([]RoleAssignment{
		{ID: "user1", Type: "user"},
		{ID: "user2", Type: "user", OUID: "ou2"},
	}, resource.Assignments)
}

// Test applyPendingShares - applies grants in declared order, defaulting an empty acting OU to owner.
func (suite *RoleExporterTestSuite) TestApplyPendingShares_Success() {
	var sharedCalls []string
	fake := &fakeSharingService{
		shareDeclarativeFunc: func(
			_ context.Context, resourceType sharing.ResourceType, resourceID, owningOUID, actingOUID string,
			_ sharing.SharePolicy,
		) ([]sharing.Grant, *tidcommon.ServiceError) {
			suite.Equal(roleSharingResourceType, resourceType)
			suite.Equal("role1", resourceID)
			suite.Equal("ou1", owningOUID)
			sharedCalls = append(sharedCalls, actingOUID)
			return nil, nil
		},
	}

	pending := []pendingShare{
		{
			role: &RoleWithPermissionsAndAssignments{ID: "role1", OUID: "ou1"},
			grants: []ShareRequest{
				{AllChildren: true},
				{InitiatingOUID: "ou1-a", OUIDs: []ShareTarget{{OUID: "ou1-a-x"}}},
			},
		},
	}

	err := applyPendingShares(pending, fake)

	suite.NoError(err)
	suite.Equal([]string{"ou1", "ou1-a"}, sharedCalls)
}

// Test applyPendingShares - propagates a Share() failure.
func (suite *RoleExporterTestSuite) TestApplyPendingShares_ShareError() {
	fake := &fakeSharingService{
		shareDeclarativeFunc: func(
			_ context.Context, _ sharing.ResourceType, _, _, _ string, _ sharing.SharePolicy,
		) ([]sharing.Grant, *tidcommon.ServiceError) {
			return nil, &sharing.ErrorInvalidTargetOU
		},
	}
	pending := []pendingShare{
		{
			role:   &RoleWithPermissionsAndAssignments{ID: "role1", OUID: "ou1"},
			grants: []ShareRequest{{AllChildren: true}},
		},
	}

	err := applyPendingShares(pending, fake)

	suite.Error(err)
	suite.Contains(err.Error(), "role1")
}

// Test parseToRoleWrapper
func (suite *RoleExporterTestSuite) TestParseToRoleWrapper() {
	yamlData := []byte(`
id: role1
name: Admin
ouId: ou1
`)

	result, err := parseToRoleWrapper(yamlData)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), result)

	role, ok := result.(*RoleWithPermissionsAndAssignments)
	assert.True(suite.T(), ok)
	assert.Equal(suite.T(), "role1", role.ID)
}

// Test resolveLoadedAssignmentOUIDs - a declarative assignment without an ouId is stamped with the
// assignee's own OU, an explicit one is preserved, and an assignee whose OU cannot be resolved falls
// back to the role's own OU rather than being left blank.
func (suite *RoleExporterTestSuite) TestResolveLoadedAssignmentOUIDs() {
	loaded := []*RoleWithPermissionsAndAssignments{
		{
			ID:   "role1",
			OUID: "ou-role",
			Assignments: []RoleAssignment{
				{ID: "user1", Type: assigneeTypeEntity},
				{ID: "user2", Type: assigneeTypeEntity, OUID: "ou-explicit"},
				{ID: "ghost", Type: assigneeTypeEntity},
			},
		},
	}

	suite.mockAssignmentService.On("ResolveAssignmentOUIDs", mock.Anything, loaded[0].Assignments).
		Return([]RoleAssignment{
			{ID: "user1", Type: assigneeTypeEntity, OUID: "ou-user1"},
			{ID: "user2", Type: assigneeTypeEntity, OUID: "ou-explicit"},
			{ID: "ghost", Type: assigneeTypeEntity},
		}, nil)

	err := resolveLoadedAssignmentOUIDs(loaded, suite.mockAssignmentService)

	suite.NoError(err)
	suite.Equal([]RoleAssignment{
		{ID: "user1", Type: assigneeTypeEntity, OUID: "ou-user1"},
		{ID: "user2", Type: assigneeTypeEntity, OUID: "ou-explicit"},
		{ID: "ghost", Type: assigneeTypeEntity, OUID: "ou-role"},
	}, loaded[0].Assignments)
}

// Test resolveLoadedAssignmentOUIDs - propagates a resolution failure.
func (suite *RoleExporterTestSuite) TestResolveLoadedAssignmentOUIDs_Error() {
	loaded := []*RoleWithPermissionsAndAssignments{
		{ID: "role1", OUID: "ou-role", Assignments: []RoleAssignment{{ID: "user1", Type: assigneeTypeEntity}}},
	}
	suite.mockAssignmentService.On("ResolveAssignmentOUIDs", mock.Anything, mock.Anything).
		Return(nil, &tidcommon.InternalServerError)

	err := resolveLoadedAssignmentOUIDs(loaded, suite.mockAssignmentService)

	suite.Error(err)
	suite.Contains(err.Error(), "role1")
}
