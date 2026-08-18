// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/group"
	"github.com/thunder-id/thunderid/internal/sharing"
	"github.com/thunder-id/thunderid/internal/system/resourcedependency"
	"github.com/thunder-id/thunderid/tests/mocks/entitymock"
	"github.com/thunder-id/thunderid/tests/mocks/entitytypemock"
	"github.com/thunder-id/thunderid/tests/mocks/groupmock"
)

// RoleAssignmentServiceTestSuite tests the roleAssignmentService.
type RoleAssignmentServiceTestSuite struct {
	suite.Suite
	mockStore             *roleStoreInterfaceMock
	mockEntityService     *entitymock.EntityServiceInterfaceMock
	mockGroupService      *groupmock.GroupServiceInterfaceMock
	mockEntityTypeService *entitytypemock.EntityTypeServiceInterfaceMock
	sharingService        *fakeSharingService
	transactioner         *fakeTransactioner
	service               RoleAssignmentServiceInterface
}

func TestRoleAssignmentServiceTestSuite(t *testing.T) {
	suite.Run(t, new(RoleAssignmentServiceTestSuite))
}

func (suite *RoleAssignmentServiceTestSuite) SetupTest() {
	suite.mockStore = newRoleStoreInterfaceMock(suite.T())
	suite.mockEntityService = entitymock.NewEntityServiceInterfaceMock(suite.T())
	suite.mockGroupService = groupmock.NewGroupServiceInterfaceMock(suite.T())
	suite.mockEntityTypeService = entitytypemock.NewEntityTypeServiceInterfaceMock(suite.T())
	suite.sharingService = &fakeSharingService{}
	suite.transactioner = &fakeTransactioner{}
	suite.service = newRoleAssignmentService(
		suite.mockStore,
		suite.mockEntityService,
		suite.mockGroupService,
		suite.mockEntityTypeService,
		suite.sharingService,
		suite.transactioner,
	)
}

// GetRoleAssignments Tests

func (suite *RoleAssignmentServiceTestSuite) TestGetRoleAssignments_Success() {
	expectedAssignments := []RoleAssignment{
		{ID: testUserID1, Type: assigneeTypeEntity},
		{ID: "group1", Type: AssigneeTypeGroup},
	}

	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockStore.On("GetRoleAssignmentsCount", mock.Anything,
		"role1", "ou1").Return(2, nil)
	suite.mockStore.On("GetRoleAssignments", mock.Anything,
		"role1", "ou1", 10, 0).Return(expectedAssignments, nil)
	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything,
		[]string{testUserID1}).Return([]providers.Entity{
		{ID: testUserID1, Category: providers.EntityCategoryUser},
	}, nil).Once()

	result, err := suite.service.GetRoleAssignments(testRootContext(), "role1", "", 10, 0, false)

	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal(2, result.TotalResults)
	suite.Equal(2, result.Count)
	suite.Equal(2, len(result.Assignments))
	suite.Equal(testUserID1, result.Assignments[0].ID)
	suite.Equal(AssigneeTypeUser, result.Assignments[0].Type)
	suite.Equal("group1", result.Assignments[1].ID)
	suite.Equal(AssigneeTypeGroup, result.Assignments[1].Type)
}

// TestGetRoleAssignments_RejectsActingOUOutsideCallerOwnOU proves a system:roles-only caller
// cannot read assignments for an acting OU other than its own token-issued OU.
func (suite *RoleAssignmentServiceTestSuite) TestGetRoleAssignments_RejectsActingOUOutsideCallerOwnOU() {
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)

	result, err := suite.service.GetRoleAssignments(testOwnOUContext("caller-ou"), "role1", "ou1", 10, 0, false)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(ErrorRoleOutsideOwnOUScope.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestGetRoleAssignments_MissingID() {
	result, err := suite.service.GetRoleAssignments(testRootContext(), "", "", 10, 0, false)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(ErrorMissingRoleID.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestGetRoleAssignments_InvalidPagination() {
	result, err := suite.service.GetRoleAssignments(testRootContext(), "role1", "", 0, 0, false)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(ErrorInvalidLimit.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestGetRoleAssignments_RoleNotFound() {
	suite.mockStore.On("GetRole", mock.Anything,
		"nonexistent").Return(RoleWithPermissions{}, ErrRoleNotFound)

	result, err := suite.service.GetRoleAssignments(testRootContext(), "nonexistent", "", 10, 0, false)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(ErrorRoleNotFound.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestGetRoleAssignments_GetRoleError() {
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{}, errors.New("database error"))

	result, err := suite.service.GetRoleAssignments(testRootContext(), "role1", "", 10, 0, false)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestGetRoleAssignments_CountError() {
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockStore.On("GetRoleAssignmentsCount", mock.Anything,
		"role1", "ou1").Return(0, errors.New("count error"))

	result, err := suite.service.GetRoleAssignments(testRootContext(), "role1", "", 10, 0, false)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestGetRoleAssignments_GetListError() {
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockStore.On("GetRoleAssignmentsCount", mock.Anything,
		"role1", "ou1").Return(2, nil)
	suite.mockStore.On("GetRoleAssignments", mock.Anything,
		"role1", "ou1", 10, 0).Return([]RoleAssignment{}, errors.New("list error"))

	result, err := suite.service.GetRoleAssignments(testRootContext(), "role1", "", 10, 0, false)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestGetRoleAssignments_WithDisplay_Success() {
	expectedAssignments := []RoleAssignment{
		{ID: testUserID1, Type: assigneeTypeEntity},
		{ID: "group1", Type: AssigneeTypeGroup},
	}

	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockStore.On("GetRoleAssignmentsCount", mock.Anything,
		"role1", "ou1").Return(2, nil)
	suite.mockStore.On("GetRoleAssignments", mock.Anything,
		"role1", "ou1", 10, 0).Return(expectedAssignments, nil)
	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything,
		[]string{testUserID1}).Return([]providers.Entity{
		{
			ID:         testUserID1,
			Category:   providers.EntityCategoryUser,
			Type:       "employee",
			Attributes: json.RawMessage(`{"email":"alice@example.com"}`),
		},
	}, nil).Once()
	suite.mockGroupService.On("GetGroupsByIDs", mock.Anything,
		[]string{"group1"}).Return(map[string]*group.Group{
		"group1": {Name: "Test Group"},
	}, (*tidcommon.ServiceError)(nil)).Once()
	suite.mockEntityTypeService.On("GetDisplayAttributesByNames", mock.Anything, mock.Anything,
		[]string{"employee"}).Return(map[string]string{
		"employee": "email",
	}, (*tidcommon.ServiceError)(nil)).Once()

	result, err := suite.service.GetRoleAssignments(testRootContext(), "role1", "", 10, 0, true)

	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal(2, result.TotalResults)
	suite.Equal(2, result.Count)
	suite.Equal(AssigneeTypeUser, result.Assignments[0].Type)
	suite.Equal(AssigneeTypeGroup, result.Assignments[1].Type)
	suite.Equal("alice@example.com", result.Assignments[0].Display)
	suite.Equal("Test Group", result.Assignments[1].Display)
}

func (suite *RoleAssignmentServiceTestSuite) TestGetRoleAssignments_WithDisplay_FallbackToID() {
	expectedAssignments := []RoleAssignment{
		{ID: testUserID1, Type: assigneeTypeEntity},
	}

	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockStore.On("GetRoleAssignmentsCount", mock.Anything,
		"role1", "ou1").Return(1, nil)
	suite.mockStore.On("GetRoleAssignments", mock.Anything,
		"role1", "ou1", 10, 0).Return(expectedAssignments, nil)
	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything,
		[]string{testUserID1}).Return([]providers.Entity{
		{ID: testUserID1},
	}, nil).Once()

	result, err := suite.service.GetRoleAssignments(testRootContext(), "role1", "", 10, 0, true)

	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal(testUserID1, result.Assignments[0].Display)
}

func (suite *RoleAssignmentServiceTestSuite) TestGetRoleAssignments_WithDisplay_FetchErrors() {
	suite.Run("User fetch error", func() {
		suite.mockStore.On("GetRole", mock.Anything, "role1").
			Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil).Once()
		suite.mockStore.On("GetRoleAssignmentsCount", mock.Anything, "role1", "ou1").Return(1, nil).Once()
		suite.mockStore.On("GetRoleAssignments", mock.Anything, "role1", "ou1", 10, 0).
			Return([]RoleAssignment{{ID: testUserID1, Type: assigneeTypeEntity}}, nil).Once()
		suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything, []string{testUserID1}).
			Return([]providers.Entity(nil), errors.New("internal error")).Once()

		result, err := suite.service.GetRoleAssignments(testRootContext(), "role1", "", 10, 0, true)

		// Entity service failure is a hard error — no silent fallback.
		suite.NotNil(err)
		suite.Nil(result)
	})

	suite.Run("Group fetch error", func() {
		suite.mockStore.On("GetRole", mock.Anything, "role1").
			Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil).Once()
		suite.mockStore.On("GetRoleAssignmentsCount", mock.Anything, "role1", "ou1").Return(1, nil).Once()
		suite.mockStore.On("GetRoleAssignments", mock.Anything, "role1", "ou1", 10, 0).
			Return([]RoleAssignment{{ID: "group1", Type: AssigneeTypeGroup}}, nil).Once()
		suite.mockGroupService.On("GetGroupsByIDs", mock.Anything, []string{"group1"}).
			Return((map[string]*group.Group)(nil), &tidcommon.ServiceError{Code: "INTERNAL_ERROR"}).Once()

		result, err := suite.service.GetRoleAssignments(testRootContext(), "role1", "", 10, 0, true)

		// Group display fetch error is a soft warning — response still returned, display falls back to ID.
		suite.Nil(err)
		suite.NotNil(result)
		suite.Equal(1, result.TotalResults)
		suite.Equal(1, result.Count)
		suite.Equal("group1", result.Assignments[0].Display)
	})
}

func (suite *RoleAssignmentServiceTestSuite) TestGetRoleAssignments_WithDisplay_PartialResults() {
	expectedAssignments := []RoleAssignment{
		{ID: testUserID1, Type: assigneeTypeEntity},
		{ID: "group1", Type: AssigneeTypeGroup},
	}

	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockStore.On("GetRoleAssignmentsCount", mock.Anything,
		"role1", "ou1").Return(2, nil)
	suite.mockStore.On("GetRoleAssignments", mock.Anything,
		"role1", "ou1", 10, 0).Return(expectedAssignments, nil)
	// Entity not found in service — orphaned assignment, skipped in output.
	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything,
		[]string{testUserID1}).Return([]providers.Entity{}, nil).Once()
	// Group found but not in map — display falls back to ID.
	suite.mockGroupService.On("GetGroupsByIDs", mock.Anything,
		[]string{"group1"}).Return(map[string]*group.Group{}, (*tidcommon.ServiceError)(nil)).Once()

	result, err := suite.service.GetRoleAssignments(testRootContext(), "role1", "", 10, 0, true)

	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal(2, result.TotalResults)
	// Orphaned entity assignment is dropped; only the group remains.
	suite.Equal(1, result.Count)
	suite.Equal("group1", result.Assignments[0].Display)
}

func (suite *RoleAssignmentServiceTestSuite) TestGetRoleAssignments_WithDisplay_NestedDisplayAttribute() {
	expectedAssignments := []RoleAssignment{
		{ID: testUserID1, Type: assigneeTypeEntity},
	}

	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockStore.On("GetRoleAssignmentsCount", mock.Anything,
		"role1", "ou1").Return(1, nil)
	suite.mockStore.On("GetRoleAssignments", mock.Anything,
		"role1", "ou1", 10, 0).Return(expectedAssignments, nil)
	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything,
		[]string{testUserID1}).Return([]providers.Entity{
		{
			ID:         testUserID1,
			Category:   providers.EntityCategoryUser,
			Type:       "employee",
			Attributes: json.RawMessage(`{"profile":{"fullName":"Alice Smith"}}`),
		},
	}, nil).Once()
	suite.mockEntityTypeService.On("GetDisplayAttributesByNames", mock.Anything, mock.Anything,
		[]string{"employee"}).Return(map[string]string{
		"employee": "profile.fullName",
	}, (*tidcommon.ServiceError)(nil)).Once()

	result, err := suite.service.GetRoleAssignments(testRootContext(), "role1", "", 10, 0, true)

	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal("Alice Smith", result.Assignments[0].Display)
}

func (suite *RoleAssignmentServiceTestSuite) TestGetRoleAssignments_WithDisplay_SchemaServiceError() {
	expectedAssignments := []RoleAssignment{
		{ID: testUserID1, Type: assigneeTypeEntity},
	}

	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockStore.On("GetRoleAssignmentsCount", mock.Anything,
		"role1", "ou1").Return(1, nil)
	suite.mockStore.On("GetRoleAssignments", mock.Anything,
		"role1", "ou1", 10, 0).Return(expectedAssignments, nil)
	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything,
		[]string{testUserID1}).Return([]providers.Entity{
		{
			ID:         testUserID1,
			Category:   providers.EntityCategoryUser,
			Type:       "employee",
			Attributes: json.RawMessage(`{"email":"alice@example.com"}`),
		},
	}, nil).Once()
	// Schema service fails — should fall back to user ID.
	suite.mockEntityTypeService.On("GetDisplayAttributesByNames", mock.Anything, mock.Anything,
		[]string{"employee"}).Return(
		(map[string]string)(nil), &tidcommon.ServiceError{Code: "INTERNAL_ERROR"},
	).Once()

	result, err := suite.service.GetRoleAssignments(testRootContext(), "role1", "", 10, 0, true)

	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal(testUserID1, result.Assignments[0].Display)
}

// GetRoleAssignmentsByType Tests

func (suite *RoleAssignmentServiceTestSuite) TestGetRoleAssignmentsByType_UserFilter_Success() {
	// Verifies that ?type=user fetches all entity assignments, filters to user-category
	// entities, paginates in memory, and returns public AssigneeTypeUser (not entity).
	suite.mockStore.On("GetRole", mock.Anything, "role1").
		Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil).Once()
	suite.mockStore.On("GetRoleAssignmentsCountByType", mock.Anything, "role1", "ou1",
		string(assigneeTypeEntity)).Return(2, nil).Once()
	suite.mockStore.On("GetRoleAssignmentsByType", mock.Anything, "role1", "ou1", 2, 0,
		string(assigneeTypeEntity)).Return([]RoleAssignment{
		{ID: testUserID1, Type: assigneeTypeEntity},
		{ID: "app-001", Type: assigneeTypeEntity},
	}, nil).Once()
	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything,
		mock.MatchedBy(func(ids []string) bool { return len(ids) == 2 })).
		Return([]providers.Entity{
			{ID: testUserID1, Category: providers.EntityCategoryUser},
			{ID: "app-001", Category: providers.EntityCategoryApp},
		}, nil).Once()
	// resolveAssignments fetches entity details for the filtered user page.
	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything,
		[]string{testUserID1}).Return([]providers.Entity{
		{ID: testUserID1, Category: providers.EntityCategoryUser},
	}, nil).Once()

	result, err := suite.service.GetRoleAssignmentsByType(testRootContext(), "role1", "", 10, 0, false, "user")

	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal(1, result.TotalResults)
	suite.Equal(1, result.Count)
	suite.Equal(1, len(result.Assignments))
	suite.Equal(testUserID1, result.Assignments[0].ID)
	suite.Equal(AssigneeTypeUser, result.Assignments[0].Type)
}

func (suite *RoleAssignmentServiceTestSuite) TestGetRoleAssignmentsByType_EntityServiceFailure() {
	// When entity service fails during category batch-fetch in getAssignmentsByEntityCategory,
	// the call should return a hard error (not a soft warn with empty results).
	suite.mockStore.On("GetRole", mock.Anything, "role1").
		Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil).Once()
	suite.mockStore.On("GetRoleAssignmentsCountByType", mock.Anything, "role1", "ou1",
		string(assigneeTypeEntity)).Return(1, nil).Once()
	suite.mockStore.On("GetRoleAssignmentsByType", mock.Anything, "role1", "ou1", 1, 0,
		string(assigneeTypeEntity)).Return([]RoleAssignment{
		{ID: testUserID1, Type: assigneeTypeEntity},
	}, nil).Once()
	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything,
		[]string{testUserID1}).Return([]providers.Entity(nil), errors.New("entity service down")).Once()

	result, err := suite.service.GetRoleAssignmentsByType(testRootContext(), "role1", "", 10, 0, false, "user")

	suite.NotNil(err)
	suite.Nil(result)
}

// AddAssignments Tests

func (suite *RoleAssignmentServiceTestSuite) TestAddAssignments_MissingRoleID() {
	request := []RoleAssignment{
		{ID: testUserID1, Type: AssigneeTypeUser},
	}

	err := suite.service.AddAssignments(testRootContext(), "", "", request)

	suite.NotNil(err)
	suite.Equal(ErrorMissingRoleID.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestAddAssignments_EmptyAssignments() {
	err := suite.service.AddAssignments(testRootContext(), "role1", "", []RoleAssignment{})

	suite.NotNil(err)
	suite.Equal(ErrorEmptyAssignments.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestAddAssignments_InvalidAssignmentFormat() {
	testCases := []struct {
		name        string
		assignment  RoleAssignment
		expectedErr string
	}{
		{
			name:        "InvalidType",
			assignment:  RoleAssignment{ID: testUserID1, Type: "invalid_type"},
			expectedErr: ErrorInvalidAssigneeType.Code,
		},
		{
			name:        "EmptyID",
			assignment:  RoleAssignment{ID: "", Type: AssigneeTypeUser},
			expectedErr: ErrorInvalidRequestFormat.Code,
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			err := suite.service.AddAssignments(testRootContext(), "role1", "", []RoleAssignment{tc.assignment})
			suite.NotNil(err)
			suite.Equal(tc.expectedErr, err.Code)
		})
	}
}

func (suite *RoleAssignmentServiceTestSuite) TestAddAssignments_RoleNotFound() {
	request := []RoleAssignment{
		{ID: testUserID1, Type: AssigneeTypeUser},
	}

	suite.mockStore.On("GetRole", mock.Anything,
		"nonexistent").Return(RoleWithPermissions{}, ErrRoleNotFound)

	err := suite.service.AddAssignments(testRootContext(), "nonexistent", "", request)

	suite.NotNil(err)
	suite.Equal(ErrorRoleNotFound.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestAddAssignments_GetRoleError() {
	request := []RoleAssignment{
		{ID: testUserID1, Type: AssigneeTypeUser},
	}

	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{}, errors.New("database error"))

	err := suite.service.AddAssignments(testRootContext(), "role1", "", request)

	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestAddAssignments_StoreError() {
	request := []RoleAssignment{
		{ID: testUserID1, Type: AssigneeTypeUser},
	}
	normalized := []RoleAssignment{
		{ID: testUserID1, Type: assigneeTypeEntity},
	}

	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything,
		[]string{testUserID1}).Return([]providers.Entity{
		{ID: testUserID1, Category: providers.EntityCategoryUser},
	}, nil)
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockStore.On("AddAssignments", mock.Anything,
		"role1", "ou1", normalized).Return(errors.New("store error"))

	err := suite.service.AddAssignments(testRootContext(), "role1", "", request)

	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestAddAssignments_Success() {
	request := []RoleAssignment{
		{ID: testUserID1, Type: AssigneeTypeUser},
	}
	normalized := []RoleAssignment{
		{ID: testUserID1, Type: assigneeTypeEntity},
	}

	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything,
		[]string{testUserID1}).Return([]providers.Entity{
		{ID: testUserID1, Category: providers.EntityCategoryUser},
	}, nil)
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockStore.On("AddAssignments", mock.Anything,
		"role1", "ou1", normalized).Return(nil)

	err := suite.service.AddAssignments(testRootContext(), "role1", "", request)

	suite.Nil(err)
}

// TestAddAssignments_RejectsActingOUOutsideCallerOwnOU proves the own-OU-scope check is additive
// to, and checked before, the existing sharing/editability checks: a system:roles-only caller
// cannot act as an OU other than its own token-issued OU, even one the role IS validly shared to.
func (suite *RoleAssignmentServiceTestSuite) TestAddAssignments_RejectsActingOUOutsideCallerOwnOU() {
	request := []RoleAssignment{{ID: testUserID1, Type: AssigneeTypeUser}}
	suite.mockStore.On("GetRole", mock.Anything, "role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)

	err := suite.service.AddAssignments(testOwnOUContext("caller-ou"), "role1", "sharee-ou", request)

	suite.NotNil(err)
	suite.Equal(ErrorRoleOutsideOwnOUScope.Code, err.Code)
}

// TestAddAssignments_AllowsCallerActingAsOwnOU proves a system:roles-only caller can add
// assignments for a role it owns, acting as its own OU.
func (suite *RoleAssignmentServiceTestSuite) TestAddAssignments_AllowsCallerActingAsOwnOU() {
	request := []RoleAssignment{{ID: testUserID1, Type: AssigneeTypeUser}}
	normalized := []RoleAssignment{{ID: testUserID1, Type: assigneeTypeEntity}}

	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything,
		[]string{testUserID1}).Return([]providers.Entity{
		{ID: testUserID1, Category: providers.EntityCategoryUser},
	}, nil)
	suite.mockStore.On("GetRole", mock.Anything, "role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockStore.On("AddAssignments", mock.Anything, "role1", "ou1", normalized).Return(nil)

	err := suite.service.AddAssignments(testOwnOUContext("ou1"), "role1", "", request)

	suite.Nil(err)
}

func (suite *RoleAssignmentServiceTestSuite) TestAddAssignments_ShareeOU_NotShared_Rejected() {
	request := []RoleAssignment{{ID: testUserID1, Type: AssigneeTypeUser}}

	suite.mockStore.On("GetRole", mock.Anything, "role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.sharingService.isSharedFunc = func(
		_ context.Context, resourceType sharing.ResourceType, resourceID, ouID string,
	) (bool, *tidcommon.ServiceError) {
		suite.Equal(roleSharingResourceType, resourceType)
		suite.Equal("role1", resourceID)
		suite.Equal("sharee-ou", ouID)
		return false, nil
	}

	err := suite.service.AddAssignments(testRootContext(), "role1", "sharee-ou", request)

	suite.NotNil(err)
	suite.Equal(ErrorRoleNotSharedToOU.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestAddAssignments_ShareeOU_NotEditable_Rejected() {
	request := []RoleAssignment{{ID: testUserID1, Type: AssigneeTypeUser}}

	suite.mockStore.On("GetRole", mock.Anything, "role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.sharingService.isSharedFunc = func(
		context.Context, sharing.ResourceType, string, string,
	) (bool, *tidcommon.ServiceError) {
		return true, nil
	}
	suite.sharingService.resolveEditabilityFunc = func(
		_ context.Context, _ sharing.ResourceType, _, _, _, fieldKey string,
	) (bool, *tidcommon.ServiceError) {
		suite.Equal(roleTemplatedFieldAssignmentsUser, fieldKey)
		return false, nil
	}

	err := suite.service.AddAssignments(testRootContext(), "role1", "sharee-ou", request)

	suite.NotNil(err)
	suite.Equal(ErrorAssignmentsNotEditable.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestAddAssignments_ShareeOU_EditabilityCheckedPerAssigneeType() {
	request := []RoleAssignment{
		{ID: testUserID1, Type: AssigneeTypeUser},
		{ID: "group1", Type: AssigneeTypeGroup},
	}

	suite.mockStore.On("GetRole", mock.Anything, "role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.sharingService.isSharedFunc = func(
		context.Context, sharing.ResourceType, string, string,
	) (bool, *tidcommon.ServiceError) {
		return true, nil
	}
	var checkedFieldKeys []string
	suite.sharingService.resolveEditabilityFunc = func(
		_ context.Context, _ sharing.ResourceType, _, _, _, fieldKey string,
	) (bool, *tidcommon.ServiceError) {
		checkedFieldKeys = append(checkedFieldKeys, fieldKey)
		// User assignments are editable, but group assignments are not: the sharee OU may add the
		// user but the whole batch must still be rejected, since it also contains a group entry.
		return fieldKey == roleTemplatedFieldAssignmentsUser, nil
	}

	err := suite.service.AddAssignments(testRootContext(), "role1", "sharee-ou", request)

	suite.NotNil(err)
	suite.Equal(ErrorAssignmentsNotEditable.Code, err.Code)
	suite.ElementsMatch(
		[]string{roleTemplatedFieldAssignmentsUser, roleTemplatedFieldAssignmentsGroup}, checkedFieldKeys)
}

func (suite *RoleAssignmentServiceTestSuite) TestAddAssignments_ShareeOU_SharedAndEditable_Success() {
	request := []RoleAssignment{{ID: testUserID1, Type: AssigneeTypeUser}}
	normalized := []RoleAssignment{{ID: testUserID1, Type: assigneeTypeEntity}}

	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything, []string{testUserID1}).
		Return([]providers.Entity{{ID: testUserID1, Category: providers.EntityCategoryUser}}, nil)
	suite.mockStore.On("GetRole", mock.Anything, "role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.sharingService.isSharedFunc = func(
		context.Context, sharing.ResourceType, string, string,
	) (bool, *tidcommon.ServiceError) {
		return true, nil
	}
	suite.sharingService.resolveEditabilityFunc = func(
		context.Context, sharing.ResourceType, string, string, string, string,
	) (bool, *tidcommon.ServiceError) {
		return true, nil
	}
	suite.mockStore.On("AddAssignments", mock.Anything, "role1", "sharee-ou", normalized).Return(nil)

	err := suite.service.AddAssignments(testRootContext(), "role1", "sharee-ou", request)

	suite.Nil(err)
}

func (suite *RoleAssignmentServiceTestSuite) TestAddAssignments_ShareeOU_IsSharedCheckError() {
	request := []RoleAssignment{{ID: testUserID1, Type: AssigneeTypeUser}}

	suite.mockStore.On("GetRole", mock.Anything, "role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.sharingService.isSharedFunc = func(
		context.Context, sharing.ResourceType, string, string,
	) (bool, *tidcommon.ServiceError) {
		return false, &tidcommon.InternalServerError
	}

	err := suite.service.AddAssignments(testRootContext(), "role1", "sharee-ou", request)

	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

// RemoveAssignments Tests

func (suite *RoleAssignmentServiceTestSuite) TestRemoveAssignments_MissingRoleID() {
	request := []RoleAssignment{
		{ID: testUserID1, Type: AssigneeTypeUser},
	}

	err := suite.service.RemoveAssignments(testRootContext(), "", "", request)

	suite.NotNil(err)
	suite.Equal(ErrorMissingRoleID.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestRemoveAssignments_EmptyAssignments() {
	err := suite.service.RemoveAssignments(testRootContext(), "role1", "", []RoleAssignment{})

	suite.NotNil(err)
	suite.Equal(ErrorEmptyAssignments.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestRemoveAssignments_RoleNotFound() {
	request := []RoleAssignment{
		{ID: testUserID1, Type: AssigneeTypeUser},
	}

	suite.mockStore.On("GetRole", mock.Anything,
		"nonexistent").Return(RoleWithPermissions{}, ErrRoleNotFound)

	err := suite.service.RemoveAssignments(testRootContext(), "nonexistent", "", request)

	suite.NotNil(err)
	suite.Equal(ErrorRoleNotFound.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestRemoveAssignments_GetRoleError() {
	request := []RoleAssignment{
		{ID: testUserID1, Type: AssigneeTypeUser},
	}

	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{}, errors.New("database error"))

	err := suite.service.RemoveAssignments(testRootContext(), "role1", "", request)

	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestRemoveAssignments_StoreError() {
	request := []RoleAssignment{
		{ID: testUserID1, Type: AssigneeTypeUser},
	}
	normalized := []RoleAssignment{
		{ID: testUserID1, Type: assigneeTypeEntity},
	}

	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything,
		[]string{testUserID1}).Return([]providers.Entity{
		{ID: testUserID1, Category: providers.EntityCategoryUser},
	}, nil)
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockStore.On("RemoveAssignments", mock.Anything,
		"role1", "ou1", normalized).Return(errors.New("store error"))

	err := suite.service.RemoveAssignments(testRootContext(), "role1", "", request)

	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestRemoveAssignments_Success() {
	request := []RoleAssignment{
		{ID: testUserID1, Type: AssigneeTypeUser},
	}
	normalized := []RoleAssignment{
		{ID: testUserID1, Type: assigneeTypeEntity},
	}

	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything,
		[]string{testUserID1}).Return([]providers.Entity{
		{ID: testUserID1, Category: providers.EntityCategoryUser},
	}, nil)
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockStore.On("RemoveAssignments", mock.Anything,
		"role1", "ou1", normalized).Return(nil)

	err := suite.service.RemoveAssignments(testRootContext(), "role1", "", request)

	suite.Nil(err)
}

func (suite *RoleAssignmentServiceTestSuite) TestGetRoleAssignments_IsRoleExist_DatabaseError() {
	suite.mockStore.On("GetRole", mock.Anything, "role1").
		Return(RoleWithPermissions{}, errors.New("mock database tracking timeout")).Once()

	result, err := suite.service.GetRoleAssignments(testRootContext(), "role1", "", 10, 0, false)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestAddAssignments_Transaction_DatabaseError() {
	assignments := []RoleAssignment{{ID: "user1", Type: "user"}}

	suite.mockStore.On("GetRole", mock.Anything, "role1").
		Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil).Once()
	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything, []string{"user1"}).
		Return([]providers.Entity{{ID: "user1", Category: providers.EntityCategoryUser}}, nil).Once()

	suite.transactioner.err = errors.New("failed to commit transaction block")

	err := suite.service.AddAssignments(testRootContext(), "role1", "", assignments)

	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestGetRoleAssignmentsByType_CountStoreError() {
	suite.mockStore.On("GetRole", mock.Anything, "role-1").
		Return(RoleWithPermissions{ID: "role-1", OUID: "ou1"}, nil).Once()

	suite.mockStore.On("GetRoleAssignmentsCountByType", mock.Anything, "role-1", "ou1", "entity").
		Return(0, errors.New("mock db counter crash")).Once()

	result, err := suite.service.GetRoleAssignmentsByType(testRootContext(), "role-1", "", 10, 0, false, "user")
	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestGetRoleAssignmentsByType_ListStoreError() {
	suite.mockStore.On("GetRole", mock.Anything, "role-1").
		Return(RoleWithPermissions{ID: "role-1", OUID: "ou1"}, nil).Once()

	suite.mockStore.On("GetRoleAssignmentsCountByType", mock.Anything, "role-1", "ou1", "entity").
		Return(1, nil).Once()

	suite.mockStore.On("GetRoleAssignmentsByType", mock.Anything, "role-1", "ou1", 1, 0, "entity").
		Return([]RoleAssignment{}, errors.New("mock db row scan failure")).Once()

	result, err := suite.service.GetRoleAssignmentsByType(testRootContext(), "role-1", "", 10, 0, false, "user")
	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

// AddAssigneesToRoles Tests

func (suite *RoleAssignmentServiceTestSuite) TestAddAssigneesToRoles_EmptyRoleIDs() {
	assignments := []RoleAssignment{{ID: testUserID1, Type: AssigneeTypeUser}}
	err := suite.service.AddAssigneesToRoles(testRootContext(), assignments, []string{})
	suite.Nil(err)
}

func (suite *RoleAssignmentServiceTestSuite) TestAddAssigneesToRoles_AddAssignmentsFails() {
	assignments := []RoleAssignment{{ID: testUserID1, Type: AssigneeTypeUser}}
	suite.mockStore.On("GetRole", mock.Anything, "role1").
		Return(RoleWithPermissions{}, ErrRoleNotFound).Once()

	err := suite.service.AddAssigneesToRoles(testRootContext(), assignments, []string{"role1"})

	suite.NotNil(err)
	suite.Equal(ErrorRoleNotFound.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestAddAssigneesToRoles_TransactionerError() {
	assignments := []RoleAssignment{{ID: testUserID1, Type: AssigneeTypeUser}}
	suite.transactioner.err = errors.New("tx begin failed")

	err := suite.service.AddAssigneesToRoles(testRootContext(), assignments, []string{"role1"})

	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

func (suite *RoleAssignmentServiceTestSuite) TestAddAssigneesToRoles_Success() {
	assignments := []RoleAssignment{{ID: testUserID1, Type: AssigneeTypeUser}}
	normalized := []RoleAssignment{{ID: testUserID1, Type: assigneeTypeEntity}}

	suite.mockStore.On("GetRole", mock.Anything, "role1").
		Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil).Once()
	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything, []string{testUserID1}).
		Return([]providers.Entity{{ID: testUserID1, Category: providers.EntityCategoryUser}}, nil).Once()
	suite.mockStore.On("AddAssignments", mock.Anything, "role1", "ou1", normalized).Return(nil).Once()

	err := suite.service.AddAssigneesToRoles(testRootContext(), assignments, []string{"role1"})

	suite.Nil(err)
}

func (suite *RoleAssignmentServiceTestSuite) TestAddAssigneesToRoles_MultipleRoles_Success() {
	assignments := []RoleAssignment{{ID: testUserID1, Type: AssigneeTypeUser}}
	normalized := []RoleAssignment{{ID: testUserID1, Type: assigneeTypeEntity}}

	suite.mockStore.On("GetRole", mock.Anything, "role1").
		Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil).Once()
	suite.mockStore.On("GetRole", mock.Anything, "role2").
		Return(RoleWithPermissions{ID: "role2", OUID: "ou2"}, nil).Once()
	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything, []string{testUserID1}).
		Return([]providers.Entity{{ID: testUserID1, Category: providers.EntityCategoryUser}}, nil).Times(2)
	suite.mockStore.On("AddAssignments", mock.Anything, "role1", "ou1", normalized).Return(nil).Once()
	suite.mockStore.On("AddAssignments", mock.Anything, "role2", "ou2", normalized).Return(nil).Once()

	err := suite.service.AddAssigneesToRoles(
		testRootContext(), assignments, []string{"role1", "role2"})

	suite.Nil(err)
}

// --- Cascade / dependency provider ---

func (suite *RoleAssignmentServiceTestSuite) TestGetAssigningOUIDs_Success() {
	suite.mockStore.On("GetAssigningOUIDs", mock.Anything, "role1").
		Return([]string{"ou1", "ou2"}, nil)

	ouIDs, err := suite.service.GetAssigningOUIDs(context.Background(), "role1")

	suite.Nil(err)
	suite.Equal([]string{"ou1", "ou2"}, ouIDs)
}

func (suite *RoleAssignmentServiceTestSuite) TestGetAssigningOUIDs_StoreError() {
	suite.mockStore.On("GetAssigningOUIDs", mock.Anything, "role1").
		Return(nil, errors.New("store error"))

	ouIDs, err := suite.service.GetAssigningOUIDs(context.Background(), "role1")

	suite.NotNil(err)
	suite.Nil(ouIDs)
}

func (suite *RoleAssignmentServiceTestSuite) TestGetResourceDependencies_ReturnsEmpty() {
	result, err := suite.service.GetResourceDependencies(
		testRootContext(), resourcedependency.ResourceTypeUser, "user-1")
	suite.NoError(err)
	suite.Empty(result)
}

func (suite *RoleAssignmentServiceTestSuite) TestCascadeDeleteDependencies_User_DeletesAssignments() {
	suite.mockStore.On("DeleteAssignmentsByAssignee", mock.Anything, string(assigneeTypeEntity), "user-1").
		Return(int64(3), nil)

	deleted, err := suite.service.CascadeDeleteDependencies(
		testRootContext(), resourcedependency.ResourceTypeUser, "user-1")

	suite.NoError(err)
	suite.Equal(3, deleted)
}

func (suite *RoleAssignmentServiceTestSuite) TestCascadeDeleteDependencies_UnknownType_NoOp() {
	deleted, err := suite.service.CascadeDeleteDependencies(testRootContext(), "theme", "theme-1")

	suite.NoError(err)
	suite.Equal(0, deleted)
	suite.mockStore.AssertNotCalled(suite.T(), "DeleteAssignmentsByAssignee",
		mock.Anything, mock.Anything, mock.Anything)
}

func (suite *RoleAssignmentServiceTestSuite) TestCascadeDeleteDependencies_StoreError() {
	suite.mockStore.On("DeleteAssignmentsByAssignee", mock.Anything, string(assigneeTypeEntity), "user-1").
		Return(int64(0), errors.New("db error"))

	deleted, err := suite.service.CascadeDeleteDependencies(
		testRootContext(), resourcedependency.ResourceTypeUser, "user-1")

	suite.Error(err)
	suite.Equal(0, deleted)
}

func (suite *RoleAssignmentServiceTestSuite) TestCascadeDeleteDependencies_Group_DeletesAssignments() {
	suite.mockStore.On("DeleteAssignmentsByAssignee", mock.Anything, string(AssigneeTypeGroup), "group-1").
		Return(int64(1), nil)

	deleted, err := suite.service.CascadeDeleteDependencies(
		testRootContext(), resourcedependency.ResourceTypeGroup, "group-1")

	suite.NoError(err)
	suite.Equal(1, deleted)
}

// Per-assignment assigning OU tests

// TestAddAssignments_PerAssignmentOUIDs_WrittenUnderTheirOwnOU proves an assignment carrying an
// explicit OUID is recorded under that OU rather than the OU the caller is acting as, and that
// assignments for different OUs are written as separate per-OU batches.
func (suite *RoleAssignmentServiceTestSuite) TestAddAssignments_PerAssignmentOUIDs_WrittenUnderTheirOwnOU() {
	request := []RoleAssignment{
		{ID: testUserID1, Type: AssigneeTypeUser},
		{ID: testUserID2, Type: AssigneeTypeUser, OUID: "sharee-ou"},
	}

	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything, mock.Anything).Return([]providers.Entity{
		{ID: testUserID1, Category: providers.EntityCategoryUser},
		{ID: testUserID2, Category: providers.EntityCategoryUser},
	}, nil)
	suite.mockStore.On("GetRole", mock.Anything, "role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.sharingService.isSharedFunc = func(
		context.Context, sharing.ResourceType, string, string,
	) (bool, *tidcommon.ServiceError) {
		return true, nil
	}
	suite.sharingService.resolveEditabilityFunc = func(
		context.Context, sharing.ResourceType, string, string, string, string,
	) (bool, *tidcommon.ServiceError) {
		return true, nil
	}
	suite.mockStore.On("AddAssignments", mock.Anything, "role1", "ou1",
		[]RoleAssignment{{ID: testUserID1, Type: assigneeTypeEntity}}).Return(nil).Once()
	suite.mockStore.On("AddAssignments", mock.Anything, "role1", "sharee-ou",
		[]RoleAssignment{{ID: testUserID2, Type: assigneeTypeEntity, OUID: "sharee-ou"}}).Return(nil).Once()

	err := suite.service.AddAssignments(testRootContext(), "role1", "", request)

	suite.Nil(err)
}

// TestAddAssignments_PerAssignmentOUID_ShareeOUAuthorizedIndependently proves the sharing gate runs
// per assigning OU, not once for the whole batch: an assignment naming an OU the role is not shared
// to is rejected even though the batch's other assignment targets the role's own OU.
func (suite *RoleAssignmentServiceTestSuite) TestAddAssignments_PerAssignmentOUID_ShareeOUAuthorizedIndependently() {
	request := []RoleAssignment{
		{ID: testUserID1, Type: AssigneeTypeUser},
		{ID: testUserID2, Type: AssigneeTypeUser, OUID: "unshared-ou"},
	}

	suite.mockStore.On("GetRole", mock.Anything, "role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.sharingService.isSharedFunc = func(
		_ context.Context, _ sharing.ResourceType, _, ouID string,
	) (bool, *tidcommon.ServiceError) {
		suite.Equal("unshared-ou", ouID)
		return false, nil
	}

	err := suite.service.AddAssignments(testRootContext(), "role1", "", request)

	suite.NotNil(err)
	suite.Equal(ErrorRoleNotSharedToOU.Code, err.Code)
}

// TestAddAssignments_PerAssignmentOUID_RejectsOUOutsideCallerOwnScope proves the own-OU-scope check
// applies to each assignment's own OU, closing the hole where a scoped caller could reach another
// OU by naming it on the assignment instead of in the acting-OU parameter.
func (suite *RoleAssignmentServiceTestSuite) TestAddAssignments_PerAssignmentOUID_RejectsOUOutsideCallerOwnScope() {
	request := []RoleAssignment{{ID: testUserID1, Type: AssigneeTypeUser, OUID: "other-ou"}}
	suite.mockStore.On("GetRole", mock.Anything, "role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)

	err := suite.service.AddAssignments(testOwnOUContext("caller-ou"), "role1", "", request)

	suite.NotNil(err)
	suite.Equal(ErrorRoleOutsideOwnOUScope.Code, err.Code)
}

// ResolveAssignmentOUIDs Tests

// TestResolveAssignmentOUIDs_FillsFromAssignee proves a blank OUID is filled from where the assignee
// itself lives, for both entity and group assignees, while an explicit OUID is left untouched.
func (suite *RoleAssignmentServiceTestSuite) TestResolveAssignmentOUIDs_FillsFromAssignee() {
	request := []RoleAssignment{
		{ID: testUserID1, Type: AssigneeTypeUser},
		{ID: "group1", Type: AssigneeTypeGroup},
		{ID: testUserID2, Type: AssigneeTypeUser, OUID: "explicit-ou"},
	}

	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything, []string{testUserID1}).
		Return([]providers.Entity{{ID: testUserID1, Category: providers.EntityCategoryUser, OUID: "user-ou"}}, nil)
	suite.mockGroupService.On("GetGroupsByIDs", mock.Anything, []string{"group1"}).
		Return(map[string]*group.Group{"group1": {ID: "group1", OUID: "group-ou"}}, nil)

	resolved, err := suite.service.ResolveAssignmentOUIDs(testRootContext(), request)

	suite.Nil(err)
	suite.Equal([]RoleAssignment{
		{ID: testUserID1, Type: AssigneeTypeUser, OUID: "user-ou"},
		{ID: "group1", Type: AssigneeTypeGroup, OUID: "group-ou"},
		{ID: testUserID2, Type: AssigneeTypeUser, OUID: "explicit-ou"},
	}, resolved)
}

// TestResolveAssignmentOUIDs_NoLookupWhenAllDeclared proves an input where every assignment already
// names its OU costs no entity or group lookup at all.
func (suite *RoleAssignmentServiceTestSuite) TestResolveAssignmentOUIDs_NoLookupWhenAllDeclared() {
	request := []RoleAssignment{{ID: testUserID1, Type: AssigneeTypeUser, OUID: "ou1"}}

	resolved, err := suite.service.ResolveAssignmentOUIDs(testRootContext(), request)

	suite.Nil(err)
	suite.Equal(request, resolved)
}

// TestResolveAssignmentOUIDs_UnknownAssigneeLeftBlank proves an assignee that cannot be found is not
// rejected here: it is left blank so the write path reports it as an invalid assignment ID.
func (suite *RoleAssignmentServiceTestSuite) TestResolveAssignmentOUIDs_UnknownAssigneeLeftBlank() {
	request := []RoleAssignment{{ID: "ghost", Type: AssigneeTypeUser}}

	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything, []string{"ghost"}).
		Return([]providers.Entity{}, nil)

	resolved, err := suite.service.ResolveAssignmentOUIDs(testRootContext(), request)

	suite.Nil(err)
	suite.Equal([]RoleAssignment{{ID: "ghost", Type: AssigneeTypeUser}}, resolved)
}
