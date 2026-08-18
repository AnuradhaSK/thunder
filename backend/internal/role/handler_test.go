// Copyright 2025 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/sharing"
	serverconst "github.com/thunder-id/thunderid/internal/system/constants"
	"github.com/thunder-id/thunderid/internal/system/error/apierror"
	"github.com/thunder-id/thunderid/internal/system/utils"
)

type RoleHandlerTestSuite struct {
	suite.Suite
	mockService           *RoleServiceInterfaceMock
	mockAssignmentService *RoleAssignmentServiceInterfaceMock
	handler               *roleHandler
}

func TestRoleHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(RoleHandlerTestSuite))
}

func (suite *RoleHandlerTestSuite) SetupTest() {
	suite.mockService = NewRoleServiceInterfaceMock(suite.T())
	suite.mockAssignmentService = NewRoleAssignmentServiceInterfaceMock(suite.T())
	suite.handler = newRoleHandler(suite.mockService, suite.mockAssignmentService, &fakeSharingService{})
}

// HandleRoleListRequest Tests
func (suite *RoleHandlerTestSuite) TestHandleRoleListRequest_Success() {
	expectedResponse := &RoleList{
		TotalResults: 2,
		StartIndex:   1,
		Count:        2,
		Roles: []Role{
			{ID: "role1", Name: "Admin"},
			{ID: "role2", Name: "User"},
		},
		Links: []utils.Link{},
	}

	suite.mockService.On("GetRoleList", mock.Anything, 10, 0).Return(expectedResponse, nil)

	req := httptest.NewRequest(http.MethodGet, "/roles?limit=10&offset=0", nil).WithContext(testRootContext())
	w := httptest.NewRecorder()

	suite.handler.HandleRoleListRequest(w, req)

	suite.Equal(http.StatusOK, w.Code)

	var response RoleListResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	suite.NoError(err)
	suite.Equal(2, response.TotalResults)
	suite.Equal(2, len(response.Roles))
}

func (suite *RoleHandlerTestSuite) TestHandleRoleListRequest_DefaultPagination() {
	expectedResponse := &RoleList{
		TotalResults: 1,
		StartIndex:   1,
		Count:        1,
		Roles:        []Role{{ID: "role1", Name: "Admin"}},
		Links:        []utils.Link{},
	}

	suite.mockService.On("GetRoleList", mock.Anything, 30, 0).Return(expectedResponse, nil)

	req := httptest.NewRequest(http.MethodGet, "/roles", nil).WithContext(testRootContext())
	w := httptest.NewRecorder()

	suite.handler.HandleRoleListRequest(w, req)

	suite.Equal(http.StatusOK, w.Code)
}

// TestHandleRoleListRequest_NoOUID_NonRootCaller_DefaultsToOwnOU proves a system:roles-only caller
// (no root permission) with no ouId query param is routed to the own-OU listing (which tags
// origin) rather than the unrestricted deployment-wide listing.
func (suite *RoleHandlerTestSuite) TestHandleRoleListRequest_NoOUID_NonRootCaller_DefaultsToOwnOU() {
	expectedResponse := &RoleListForOU{
		TotalResults: 1,
		StartIndex:   1,
		Count:        1,
		Roles:        []RoleForOU{{Role: Role{ID: "role1", Name: "Admin", OUID: "caller-ou"}, Origin: RoleOriginOwned}},
		Links:        []utils.Link{},
	}
	suite.mockService.On("GetRolesForOU", mock.Anything, "caller-ou", 30, 0).Return(expectedResponse, nil)

	req := httptest.NewRequest(http.MethodGet, "/roles", nil).WithContext(testOwnOUContext("caller-ou"))
	w := httptest.NewRecorder()

	suite.handler.HandleRoleListRequest(w, req)

	suite.Equal(http.StatusOK, w.Code)
	var response RoleListForOUResponse
	suite.NoError(json.NewDecoder(w.Body).Decode(&response))
	suite.Equal(1, response.TotalResults)
	suite.Require().Len(response.Roles, 1)
	suite.Equal("owned", response.Roles[0].Origin)
	suite.mockService.AssertNotCalled(suite.T(), "GetRoleList", mock.Anything, mock.Anything, mock.Anything)
}

func (suite *RoleHandlerTestSuite) TestHandleRoleListRequest_ServiceError() {
	suite.mockService.On("GetRoleList", mock.Anything, 10, 0).Return(nil, &ErrorInvalidLimit)

	req := httptest.NewRequest(http.MethodGet, "/roles?limit=10&offset=0", nil).WithContext(testRootContext())
	w := httptest.NewRecorder()

	suite.handler.HandleRoleListRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

// HandleRolePostRequest Tests
func (suite *RoleHandlerTestSuite) TestHandleRolePostRequest_Success() {
	request := CreateRoleRequest{
		Name:        "Test Role",
		Description: "Description",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
	}

	expectedRole := &RoleWithPermissionsAndAssignments{
		ID:          "role1",
		Name:        "Test Role",
		Description: "Description",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
	}

	suite.mockService.On("CreateRole", mock.Anything, mock.AnythingOfType("RoleCreationDetail")).
		Return(expectedRole, nil)

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/roles", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	suite.handler.HandleRolePostRequest(w, req)

	suite.Equal(http.StatusCreated, w.Code)

	var response CreateRoleResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	suite.NoError(err)
	suite.Equal("role1", response.ID)
	suite.Equal("Test Role", response.Name)
}

func (suite *RoleHandlerTestSuite) TestHandleRolePostRequest_WithoutPermissions_ReturnsEmptyArray() {
	request := CreateRoleRequest{
		Name: "Test Role",
		OUID: "ou1",
	}

	expectedRole := &RoleWithPermissionsAndAssignments{
		ID:   "role1",
		Name: "Test Role",
		OUID: "ou1",
	}

	suite.mockService.On("CreateRole", mock.Anything, mock.AnythingOfType("RoleCreationDetail")).
		Return(expectedRole, nil)

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/roles", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	suite.handler.HandleRolePostRequest(w, req)

	suite.Equal(http.StatusCreated, w.Code)

	var response CreateRoleResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	suite.NoError(err)
	suite.NotNil(response.Permissions)
	suite.Empty(response.Permissions)
}

func (suite *RoleHandlerTestSuite) TestHandleRolePostRequest_InvalidJSON() {
	req := httptest.NewRequest(http.MethodPost, "/roles", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	suite.handler.HandleRolePostRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

func (suite *RoleHandlerTestSuite) TestHandleRolePostRequest_ServiceError() {
	request := CreateRoleRequest{
		Name:        "Test Role",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
	}

	suite.mockService.On("CreateRole", mock.Anything, mock.AnythingOfType("RoleCreationDetail")).
		Return(nil, &ErrorOrganizationUnitNotFound)

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/roles", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	suite.handler.HandleRolePostRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

func (suite *RoleHandlerTestSuite) TestHandleRolePostRequest_ValidationError_NameTooLong() {
	request := CreateRoleRequest{
		Name: strings.Repeat("a", 101),
		OUID: "ou-tenancy-1",
	}

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/roles", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	suite.handler.HandleRolePostRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
	suite.Contains(w.Body.String(), "INVALID_INPUT_METADATA")

	suite.mockService.AssertNotCalled(suite.T(), "CreateRole", mock.Anything, mock.Anything)
}

func (suite *RoleHandlerTestSuite) TestHandleRoleAddAssignmentsRequest_ValidationError_TypeSpoof() {
	body := `{"assignments":[]}`
	req := httptest.NewRequest(http.MethodPost, "/roles/role1/add-assignments", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleAddAssignmentsRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
	suite.Contains(w.Body.String(), "Invalid request format")

	suite.mockAssignmentService.AssertNotCalled(
		suite.T(), "AddAssignments", mock.Anything, mock.Anything, mock.Anything)
}

// HandleRoleGetRequest Tests
func (suite *RoleHandlerTestSuite) TestHandleRoleGetRequest_Success() {
	expectedRole := &RoleWithPermissions{
		ID:          "role1",
		Name:        "Admin",
		Description: "Admin role",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
	}

	suite.mockService.On("GetRoleWithPermissions", mock.Anything, "role1").Return(expectedRole, nil)

	req := httptest.NewRequest(http.MethodGet, "/roles/role1", nil)
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleGetRequest(w, req)

	suite.Equal(http.StatusOK, w.Code)

	var response RoleResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	suite.NoError(err)
	suite.Equal("role1", response.ID)
	suite.Equal("Admin", response.Name)
}

func (suite *RoleHandlerTestSuite) TestHandleRoleGetRequest_MissingID() {
	suite.mockService.On("GetRoleWithPermissions", mock.Anything, "").Return(nil, &ErrorMissingRoleID)

	req := httptest.NewRequest(http.MethodGet, "/roles/", nil)
	w := httptest.NewRecorder()

	suite.handler.HandleRoleGetRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

func (suite *RoleHandlerTestSuite) TestHandleRoleGetRequest_NotFound() {
	suite.mockService.On("GetRoleWithPermissions", mock.Anything, "nonexistent").Return(nil, &ErrorRoleNotFound)

	req := httptest.NewRequest(http.MethodGet, "/roles/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleGetRequest(w, req)

	suite.Equal(http.StatusNotFound, w.Code)
}

// HandleRolePutRequest Tests
func (suite *RoleHandlerTestSuite) TestHandleRolePutRequest_Success() {
	request := UpdateRoleRequest{
		Name:        "Updated Role",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1", "perm2"}}},
	}

	updatedRole := &RoleWithPermissions{
		ID:          "role1",
		Name:        "Updated Role",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1", "perm2"}}},
	}

	suite.mockService.On("UpdateRoleWithPermissions", mock.Anything, "role1",
		mock.AnythingOfType("RoleUpdateDetail")).Return(updatedRole, nil)

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPut, "/roles/role1", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRolePutRequest(w, req)

	suite.Equal(http.StatusOK, w.Code)

	var response RoleResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	suite.NoError(err)
	suite.Equal("Updated Role", response.Name)
}

func (suite *RoleHandlerTestSuite) TestHandleRolePutRequest_InvalidJSON() {
	req := httptest.NewRequest(http.MethodPut, "/roles/role1", bytes.NewBufferString("invalid"))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRolePutRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

// HandleRoleDeleteRequest Tests
func (suite *RoleHandlerTestSuite) TestHandleRoleDeleteRequest_Success() {
	suite.mockService.On("DeleteRole", mock.Anything, "role1").Return(nil)

	req := httptest.NewRequest(http.MethodDelete, "/roles/role1", nil)
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleDeleteRequest(w, req)

	suite.Equal(http.StatusNoContent, w.Code)
}

// HandleRoleAssignmentsGetRequest Tests
func (suite *RoleHandlerTestSuite) TestHandleRoleAssignmentsGetRequest_Success() {
	expectedResponse := &AssignmentList{
		TotalResults: 2,
		StartIndex:   1,
		Count:        2,
		Assignments: []RoleAssignmentWithDisplay{
			{ID: "user1", Type: AssigneeTypeUser},
			{ID: "group1", Type: AssigneeTypeGroup},
		},
		Links: []utils.Link{},
	}

	suite.mockAssignmentService.On("GetRoleAssignments", mock.Anything, "role1", "", 10, 0, false).
		Return(expectedResponse, nil)

	req := httptest.NewRequest(http.MethodGet, "/roles/role1/assignments?limit=10&offset=0", nil)
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleAssignmentsGetRequest(w, req)

	suite.Equal(http.StatusOK, w.Code)

	var response AssignmentListResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	suite.NoError(err)
	suite.Equal(2, response.TotalResults)
	suite.Equal(2, len(response.Assignments))
}

func (suite *RoleHandlerTestSuite) TestHandleRoleAssignmentsGetRequest_RoleNotFound() {
	suite.mockAssignmentService.On("GetRoleAssignments", mock.Anything, "nonexistent", "", 30, 0, false).
		Return(nil, &ErrorRoleNotFound)

	req := httptest.NewRequest(http.MethodGet, "/roles/nonexistent/assignments", nil)
	req.SetPathValue("id", "nonexistent")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleAssignmentsGetRequest(w, req)

	suite.Equal(http.StatusNotFound, w.Code)
}

// HandleRoleAddAssignmentsRequest Tests
func (suite *RoleHandlerTestSuite) TestHandleRoleAddAssignmentsRequest_Success() {
	request := AssignmentsRequest{
		Assignments: []AssignmentRequest{
			{ID: "user1", Type: AssigneeTypeUser},
		},
	}

	suite.mockAssignmentService.On(
		"AddAssignments", mock.Anything, "role1", "", mock.AnythingOfType("[]role.RoleAssignment"),
	).Return(nil)

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/roles/role1/add-assignments", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleAddAssignmentsRequest(w, req)

	suite.Equal(http.StatusNoContent, w.Code)
}

func (suite *RoleHandlerTestSuite) TestHandleRoleAddAssignmentsRequest_InvalidJSON() {
	req := httptest.NewRequest(http.MethodPost, "/roles/role1/add-assignments", bytes.NewBufferString("invalid"))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleAddAssignmentsRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

func (suite *RoleHandlerTestSuite) TestHandleRoleAddAssignmentsRequest_ServiceError() {
	request := AssignmentsRequest{
		Assignments: []AssignmentRequest{
			{ID: "invalid_user", Type: AssigneeTypeUser},
		},
	}

	suite.mockAssignmentService.On(
		"AddAssignments", mock.Anything, "role1", "", mock.AnythingOfType("[]role.RoleAssignment"),
	).Return(&ErrorInvalidAssignmentID)

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/roles/role1/add-assignments", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleAddAssignmentsRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

// HandleRoleRemoveAssignmentsRequest Tests
func (suite *RoleHandlerTestSuite) TestHandleRoleRemoveAssignmentsRequest_Success() {
	request := AssignmentsRequest{
		Assignments: []AssignmentRequest{
			{ID: "user1", Type: AssigneeTypeUser},
		},
	}

	suite.mockAssignmentService.On(
		"RemoveAssignments", mock.Anything, "role1", "", mock.AnythingOfType("[]role.RoleAssignment"),
	).Return(nil)

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/roles/role1/remove-assignments", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleRemoveAssignmentsRequest(w, req)

	suite.Equal(http.StatusNoContent, w.Code)
}

// ParsePaginationParams Tests
func (suite *RoleHandlerTestSuite) TestParsePaginationParams() {
	testCases := []struct {
		name           string
		queryString    string
		expectedLimit  int
		expectedOffset int
		expectError    bool
	}{
		{
			name:           "ValidParams",
			queryString:    "limit=20&offset=10",
			expectedLimit:  20,
			expectedOffset: 10,
			expectError:    false,
		},
		{
			name:           "DefaultLimit",
			queryString:    "offset=5",
			expectedLimit:  30,
			expectedOffset: 5,
			expectError:    false,
		},
		{
			name:           "NoParams",
			queryString:    "",
			expectedLimit:  30,
			expectedOffset: 0,
			expectError:    false,
		},
		{
			name:           "InvalidLimit",
			queryString:    "limit=abc",
			expectedLimit:  0,
			expectedOffset: 0,
			expectError:    true,
		},
		{
			name:           "InvalidOffset",
			queryString:    "offset=xyz",
			expectedLimit:  0,
			expectedOffset: 0,
			expectError:    true,
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			query, _ := url.ParseQuery(tc.queryString)
			limit, offset, err := parsePaginationParams(query)

			if tc.expectError {
				suite.NotNil(err)
			} else {
				suite.Nil(err)
				suite.Equal(tc.expectedLimit, limit)
				suite.Equal(tc.expectedOffset, offset)
			}
		})
	}
}

// HandleRolePutRequest additional tests
func (suite *RoleHandlerTestSuite) TestHandleRolePutRequest_MissingID() {
	request := UpdateRoleRequest{
		Name:        "Updated Role",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
	}

	suite.mockService.On("UpdateRoleWithPermissions", mock.Anything, "", mock.AnythingOfType("RoleUpdateDetail")).
		Return(nil, &ErrorMissingRoleID)

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPut, "/roles/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	suite.handler.HandleRolePutRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

func (suite *RoleHandlerTestSuite) TestHandleRolePutRequest_RoleNotFound() {
	request := UpdateRoleRequest{
		Name:        "Updated Role",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
	}

	suite.mockService.On("UpdateRoleWithPermissions", mock.Anything, "nonexistent",
		mock.AnythingOfType("RoleUpdateDetail")).
		Return(nil, &ErrorRoleNotFound)

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPut, "/roles/nonexistent", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", "nonexistent")
	w := httptest.NewRecorder()

	suite.handler.HandleRolePutRequest(w, req)

	suite.Equal(http.StatusNotFound, w.Code)
}

// HandleRoleDeleteRequest additional tests
func (suite *RoleHandlerTestSuite) TestHandleRoleDeleteRequest_MissingID() {
	suite.mockService.On("DeleteRole", mock.Anything, "").Return(&ErrorMissingRoleID)

	req := httptest.NewRequest(http.MethodDelete, "/roles/", nil)
	w := httptest.NewRecorder()

	suite.handler.HandleRoleDeleteRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

func (suite *RoleHandlerTestSuite) TestHandleRoleDeleteRequest_RoleNotFound() {
	suite.mockService.On("DeleteRole", mock.Anything, "nonexistent").Return(&ErrorRoleNotFound)

	req := httptest.NewRequest(http.MethodDelete, "/roles/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleDeleteRequest(w, req)

	suite.Equal(http.StatusNotFound, w.Code)
}

// HandleRoleAssignmentsGetRequest additional tests
func (suite *RoleHandlerTestSuite) TestHandleRoleAssignmentsGetRequest_MissingID() {
	suite.mockAssignmentService.On("GetRoleAssignments", mock.Anything, "", "", 30, 0, false).
		Return(nil, &ErrorMissingRoleID)

	req := httptest.NewRequest(http.MethodGet, "/roles//assignments", nil)
	w := httptest.NewRecorder()

	suite.handler.HandleRoleAssignmentsGetRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

func (suite *RoleHandlerTestSuite) TestHandleRoleAssignmentsGetRequest_InvalidPagination() {
	req := httptest.NewRequest(http.MethodGet, "/roles/role1/assignments?limit=invalid", nil)
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleAssignmentsGetRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

// HandleRoleAddAssignmentsRequest additional tests
func (suite *RoleHandlerTestSuite) TestHandleRoleAddAssignmentsRequest_MissingID() {
	request := AssignmentsRequest{
		Assignments: []AssignmentRequest{
			{ID: "user1", Type: AssigneeTypeUser},
		},
	}

	suite.mockAssignmentService.On("AddAssignments",
		mock.Anything, "", "", mock.AnythingOfType("[]role.RoleAssignment")).
		Return(&ErrorMissingRoleID)

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/roles//add-assignments", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleAddAssignmentsRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

func (suite *RoleHandlerTestSuite) TestHandleRoleAddAssignmentsRequest_RoleNotFound() {
	request := AssignmentsRequest{
		Assignments: []AssignmentRequest{
			{ID: "user1", Type: AssigneeTypeUser},
		},
	}

	suite.mockAssignmentService.On(
		"AddAssignments", mock.Anything, "nonexistent", "", mock.AnythingOfType("[]role.RoleAssignment"),
	).Return(&ErrorRoleNotFound)

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/roles/nonexistent/add-assignments", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", "nonexistent")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleAddAssignmentsRequest(w, req)

	suite.Equal(http.StatusNotFound, w.Code)
}

// HandleRoleRemoveAssignmentsRequest additional tests
func (suite *RoleHandlerTestSuite) TestHandleRoleRemoveAssignmentsRequest_MissingID() {
	request := AssignmentsRequest{
		Assignments: []AssignmentRequest{
			{ID: "user1", Type: AssigneeTypeUser},
		},
	}

	suite.mockAssignmentService.On(
		"RemoveAssignments", mock.Anything, "", "", mock.AnythingOfType("[]role.RoleAssignment"),
	).Return(&ErrorMissingRoleID)

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/roles//remove-assignments", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleRemoveAssignmentsRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

func (suite *RoleHandlerTestSuite) TestHandleRoleRemoveAssignmentsRequest_InvalidJSON() {
	req := httptest.NewRequest(http.MethodPost, "/roles/role1/remove-assignments", bytes.NewBufferString("invalid"))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleRemoveAssignmentsRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

func (suite *RoleHandlerTestSuite) TestHandleRoleRemoveAssignmentsRequest_RoleNotFound() {
	request := AssignmentsRequest{
		Assignments: []AssignmentRequest{
			{ID: "user1", Type: AssigneeTypeUser},
		},
	}

	suite.mockAssignmentService.On("RemoveAssignments", mock.Anything, "nonexistent", "",
		mock.AnythingOfType("[]role.RoleAssignment")).
		Return(&ErrorRoleNotFound)

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/roles/nonexistent/remove-assignments", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", "nonexistent")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleRemoveAssignmentsRequest(w, req)

	suite.Equal(http.StatusNotFound, w.Code)
}

func (suite *RoleHandlerTestSuite) TestHandleRoleRemoveAssignmentsRequest_ServiceError() {
	request := AssignmentsRequest{
		Assignments: []AssignmentRequest{
			{ID: "user1", Type: AssigneeTypeUser},
		},
	}

	suite.mockAssignmentService.On(
		"RemoveAssignments", mock.Anything, "role1", "", mock.AnythingOfType("[]role.RoleAssignment"),
	).Return(&ErrorInvalidAssignmentID)

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/roles/role1/remove-assignments", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleRemoveAssignmentsRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

// Sanitization Tests
func (suite *RoleHandlerTestSuite) TestSanitizeCreateRoleRequest() {
	request := &CreateRoleRequest{
		Name:        "  Test Role  ",
		Description: "  Description  ",
		OUID:        "  ou1  ",
		Permissions: []ResourcePermissions{
			{
				ResourceServerID: "  rs1  ",
				Permissions:      []string{"  perm1  ", "  perm2  "},
			},
		},
		Assignments: []AssignmentRequest{
			{ID: "  user1  ", Type: AssigneeTypeUser},
		},
	}

	sanitized := suite.handler.sanitizeCreateRoleRequest(request)

	suite.Equal("Test Role", sanitized.Name)
	suite.Equal("Description", sanitized.Description)
	suite.Equal("ou1", sanitized.OUID)
	suite.Equal("rs1", sanitized.Permissions[0].ResourceServerID)
	suite.Equal("perm1", sanitized.Permissions[0].Permissions[0])
	suite.Equal("user1", sanitized.Assignments[0].ID)
}

func (suite *RoleHandlerTestSuite) TestSanitizeUpdateRoleRequest() {
	request := &UpdateRoleRequest{
		Name:        "  Updated Name  ",
		OUID:        "  ou2  ",
		Permissions: []ResourcePermissions{{ResourceServerID: "  rs2  ", Permissions: []string{"  perm3  "}}},
	}

	sanitized := suite.handler.sanitizeUpdateRoleRequest(request)

	suite.Equal("Updated Name", sanitized.Name)
	suite.Equal("ou2", sanitized.OUID)
	suite.Equal("rs2", sanitized.Permissions[0].ResourceServerID)
	suite.Equal("perm3", sanitized.Permissions[0].Permissions[0])
}

func (suite *RoleHandlerTestSuite) TestSanitizeCreateRoleRequest_PreservesSpecialCharacters() {
	request := &CreateRoleRequest{
		Name:        "  Dean's Sub team  ",
		Description: `  R&D <team> "core"  `,
	}

	sanitized := suite.handler.sanitizeCreateRoleRequest(request)

	suite.Equal("Dean's Sub team", sanitized.Name)
	suite.Equal(`R&D <team> "core"`, sanitized.Description)
}

func (suite *RoleHandlerTestSuite) TestSanitizeUpdateRoleRequest_PreservesSpecialCharacters() {
	request := &UpdateRoleRequest{
		Name:        "  Dean's Sub team  ",
		Description: `  R&D <team> "core"  `,
	}

	sanitized := suite.handler.sanitizeUpdateRoleRequest(request)

	suite.Equal("Dean's Sub team", sanitized.Name)
	suite.Equal(`R&D <team> "core"`, sanitized.Description)
}

// The Console echoes the stored name back on every save. Replaying that loop must not drift the name.
func (suite *RoleHandlerTestSuite) TestSanitizeUpdateRoleRequestIsIdempotentAcrossSaves() {
	name := suite.handler.sanitizeCreateRoleRequest(&CreateRoleRequest{
		Name: "Dean's Sub team",
	}).Name

	for i := 0; i < 5; i++ {
		sanitized := suite.handler.sanitizeUpdateRoleRequest(&UpdateRoleRequest{
			Name:        name,
			Description: "save " + strconv.Itoa(i),
		})
		suite.Equal("Dean's Sub team", sanitized.Name)
		name = sanitized.Name
	}
}

func (suite *RoleHandlerTestSuite) TestSanitizeAssignmentsRequest() {
	request := &AssignmentsRequest{
		Assignments: []AssignmentRequest{
			{ID: "  group1  ", Type: AssigneeTypeGroup},
		},
	}

	sanitized := suite.handler.sanitizeAssignmentsRequest(request)

	suite.Equal("group1", sanitized.Assignments[0].ID)
	suite.Equal(AssigneeTypeGroup, sanitized.Assignments[0].Type)
}

// handleError coverage
func (suite *RoleHandlerTestSuite) TestHandleError_ClientAndServerErrors() {
	suite.T().Run("Client_NotFound", func(t *testing.T) {
		w := httptest.NewRecorder()

		handleError(context.Background(), w, &ErrorRoleNotFound)

		suite.Equal(http.StatusNotFound, w.Code)
		var resp apierror.ErrorResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		suite.NoError(err)
		suite.Equal(ErrorRoleNotFound.Code, resp.Code)
	})

	suite.T().Run("ServerError", func(t *testing.T) {
		w := httptest.NewRecorder()

		handleError(context.Background(), w, &tidcommon.InternalServerError)

		suite.Equal(http.StatusInternalServerError, w.Code)
		var resp apierror.ErrorResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		suite.NoError(err)
		suite.Equal(tidcommon.InternalServerError.Code, resp.Code)
	})

	suite.T().Run("Client_DeletionRestrictedToOwner", func(t *testing.T) {
		w := httptest.NewRecorder()

		handleError(context.Background(), w, &ErrorRoleDeletionRestrictedToOwner)

		suite.Equal(http.StatusForbidden, w.Code)
		var resp apierror.ErrorResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		suite.NoError(err)
		suite.Equal(ErrorRoleDeletionRestrictedToOwner.Code, resp.Code)
	})
}

// HandleRoleGrantsPostRequest Tests

func (suite *RoleHandlerTestSuite) TestHandleRoleGrantsPostRequest_RootTargeting_Success() {
	suite.mockService.On("GetRoleWithPermissions", mock.Anything, "role1").
		Return(&RoleWithPermissions{ID: "role1", OUID: "owner-ou"}, nil)

	fakeSharing := &fakeSharingService{
		shareFunc: func(
			_ context.Context, resourceType sharing.ResourceType, resourceID, owningOUID, actingOUID string,
			policy sharing.SharePolicy,
		) ([]sharing.Grant, *tidcommon.ServiceError) {
			suite.Equal(roleSharingResourceType, resourceType)
			suite.Equal("role1", resourceID)
			suite.Equal("owner-ou", owningOUID)
			// ouId omitted in the request => acting OU defaults to the role's own owner.
			suite.Equal("owner-ou", actingOUID)
			suite.True(policy.AllRoots)
			suite.Equal([]string{"excludedRoot1"}, policy.ExcludedRootOUIDs)
			return []sharing.Grant{
				{ID: "grant1", Stage: sharing.StageShare, TargetScope: sharing.TargetScopeAllRoots,
					OwningOUID: "owner-ou", ExcludedOUIDs: []string{"excludedRoot1"}},
			}, nil
		},
	}
	suite.handler = newRoleHandler(suite.mockService, suite.mockAssignmentService, fakeSharing)

	body, _ := json.Marshal(ShareRequest{AllRoots: true, ExcludedRootOUIDs: []string{"excludedRoot1"}})
	req := httptest.NewRequest(http.MethodPost, "/roles/role1/grants", bytes.NewBuffer(body))
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleGrantsPostRequest(w, req)

	suite.Equal(http.StatusCreated, w.Code)
	var response GrantListResponse
	suite.NoError(json.NewDecoder(w.Body).Decode(&response))
	suite.Len(response.Grants, 1)
	suite.Equal("grant1", response.Grants[0].ID)
	suite.Equal("share", response.Grants[0].Stage)
	suite.Equal("all_roots", response.Grants[0].TargetScope)
	suite.Equal([]string{"excludedRoot1"}, response.Grants[0].ExcludedOUIDs)
}

// A declaratively defined role is grantable through the API like any other: only the grants its
// file declares are immutable, not the role's ability to gain further ones.
func (suite *RoleHandlerTestSuite) TestHandleRoleGrantsPostRequest_DeclarativeRoleIsGrantable() {
	suite.mockService.On("GetRoleWithPermissions", mock.Anything, "decl-role").
		Return(&RoleWithPermissions{ID: "decl-role", OUID: "owner-ou"}, nil)

	fakeSharing := &fakeSharingService{
		shareFunc: func(
			_ context.Context, _ sharing.ResourceType, resourceID, owningOUID, _ string,
			_ sharing.SharePolicy,
		) ([]sharing.Grant, *tidcommon.ServiceError) {
			suite.Equal("decl-role", resourceID)
			suite.Equal("owner-ou", owningOUID)
			return []sharing.Grant{{ID: "grant1", Stage: sharing.StageShare,
				TargetScope: sharing.TargetScopeAllChildren, OwningOUID: "owner-ou"}}, nil
		},
	}
	suite.handler = newRoleHandler(suite.mockService, suite.mockAssignmentService, fakeSharing)

	body, _ := json.Marshal(ShareRequest{AllChildren: true})
	req := httptest.NewRequest(http.MethodPost, "/roles/decl-role/grants", bytes.NewBuffer(body))
	req.SetPathValue("id", "decl-role")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleGrantsPostRequest(w, req)

	suite.Equal(http.StatusCreated, w.Code)
	var response GrantListResponse
	suite.NoError(json.NewDecoder(w.Body).Decode(&response))
	suite.Require().Len(response.Grants, 1)
	suite.Equal("grant1", response.Grants[0].ID)
}

func (suite *RoleHandlerTestSuite) TestHandleRoleGrantsPostRequest_InvalidBody() {
	req := httptest.NewRequest(http.MethodPost, "/roles/role1/grants", bytes.NewBufferString("not json"))
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleGrantsPostRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

func (suite *RoleHandlerTestSuite) TestHandleRoleGrantsPostRequest_RoleNotFound() {
	suite.mockService.On("GetRoleWithPermissions", mock.Anything, "missing").Return(nil, &ErrorRoleNotFound)

	body, _ := json.Marshal(ShareRequest{AllRoots: true})
	req := httptest.NewRequest(http.MethodPost, "/roles/missing/grants", bytes.NewBuffer(body))
	req.SetPathValue("id", "missing")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleGrantsPostRequest(w, req)

	suite.Equal(http.StatusNotFound, w.Code)
}

func (suite *RoleHandlerTestSuite) TestHandleRoleGrantsPostRequest_SharingServiceError() {
	suite.mockService.On("GetRoleWithPermissions", mock.Anything, "role1").
		Return(&RoleWithPermissions{ID: "role1", OUID: "owner-ou"}, nil)
	fakeSharing := &fakeSharingService{
		shareFunc: func(
			_ context.Context, _ sharing.ResourceType, _, _, _ string, _ sharing.SharePolicy,
		) ([]sharing.Grant, *tidcommon.ServiceError) {
			return nil, &sharing.ErrorInvalidTargetOU
		},
	}
	suite.handler = newRoleHandler(suite.mockService, suite.mockAssignmentService, fakeSharing)

	body, _ := json.Marshal(ShareRequest{RootOUIDs: []string{"not-a-root"}})
	req := httptest.NewRequest(http.MethodPost, "/roles/role1/grants", bytes.NewBuffer(body))
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleGrantsPostRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

func (suite *RoleHandlerTestSuite) TestHandleRoleGrantsPostRequest_ChildrenTargeting_ExplicitOUID_Success() {
	suite.mockService.On("GetRoleWithPermissions", mock.Anything, "role1").
		Return(&RoleWithPermissions{ID: "role1", OUID: "owner-ou"}, nil)

	fakeSharing := &fakeSharingService{
		shareFunc: func(
			_ context.Context, resourceType sharing.ResourceType, resourceID, owningOUID, actingOUID string,
			policy sharing.SharePolicy,
		) ([]sharing.Grant, *tidcommon.ServiceError) {
			suite.Equal(roleSharingResourceType, resourceType)
			suite.Equal("role1", resourceID)
			suite.Equal("owner-ou", owningOUID)
			// An explicit ouId (a sharee resharing further) flows through as the acting OU.
			suite.Equal("root1", actingOUID)
			suite.True(policy.AllChildren)
			suite.Equal([]string{"excludedChild1"}, policy.ExcludedOUIDs)
			return []sharing.Grant{
				{ID: "grant2", Stage: sharing.StageReshare, TargetScope: sharing.TargetScopeAllChildren,
					TargetOUID: "root1", ExcludedOUIDs: []string{"excludedChild1"}},
			}, nil
		},
	}
	suite.handler = newRoleHandler(suite.mockService, suite.mockAssignmentService, fakeSharing)

	body, _ := json.Marshal(ShareRequest{
		InitiatingOUID: "root1", AllChildren: true, ExcludedOUIDs: []string{"excludedChild1"},
	})
	req := httptest.NewRequest(http.MethodPost, "/roles/role1/grants", bytes.NewBuffer(body))
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleGrantsPostRequest(w, req)

	suite.Equal(http.StatusCreated, w.Code)
	var response GrantListResponse
	suite.NoError(json.NewDecoder(w.Body).Decode(&response))
	suite.Len(response.Grants, 1)
	suite.Equal("reshare", response.Grants[0].Stage)
	suite.Equal("all_children", response.Grants[0].TargetScope)
	suite.Equal([]string{"excludedChild1"}, response.Grants[0].ExcludedOUIDs)
}

func (suite *RoleHandlerTestSuite) TestHandleRoleGrantsPostRequest_ChildrenTargeting_SharingServiceError() {
	suite.mockService.On("GetRoleWithPermissions", mock.Anything, "role1").
		Return(&RoleWithPermissions{ID: "role1", OUID: "owner-ou"}, nil)

	fakeSharing := &fakeSharingService{
		shareFunc: func(
			_ context.Context, _ sharing.ResourceType, _, _, _ string, _ sharing.SharePolicy,
		) ([]sharing.Grant, *tidcommon.ServiceError) {
			return nil, &sharing.ErrorNotShared
		},
	}
	suite.handler = newRoleHandler(suite.mockService, suite.mockAssignmentService, fakeSharing)

	body, _ := json.Marshal(ShareRequest{InitiatingOUID: "root1", AllChildren: true})
	req := httptest.NewRequest(http.MethodPost, "/roles/role1/grants", bytes.NewBuffer(body))
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleGrantsPostRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

// HandleRoleGrantsGetRequest Tests

func (suite *RoleHandlerTestSuite) TestHandleRoleGrantsGetRequest_Success() {
	fakeSharing := &fakeSharingService{
		listGrantsPageFunc: func(
			_ context.Context, resourceType sharing.ResourceType, resourceID string, limit, offset int,
		) (*sharing.GrantPage, *tidcommon.ServiceError) {
			suite.Equal(roleSharingResourceType, resourceType)
			suite.Equal("role1", resourceID)
			// No limit/offset in the query string, so the default page size applies.
			suite.Equal(serverconst.DefaultPageSize, limit)
			suite.Equal(0, offset)
			return &sharing.GrantPage{
				Grants: []sharing.Grant{
					{
						ID: "grant1", Stage: sharing.StageShare,
						TargetScope: sharing.TargetScopeRoot, TargetOUID: "root1",
					},
				},
				TotalResults: 1,
			}, nil
		},
	}
	suite.handler = newRoleHandler(suite.mockService, suite.mockAssignmentService, fakeSharing)

	req := httptest.NewRequest(http.MethodGet, "/roles/role1/grants", nil)
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleGrantsGetRequest(w, req)

	suite.Equal(http.StatusOK, w.Code)
	var response GrantListResponse
	suite.NoError(json.NewDecoder(w.Body).Decode(&response))
	suite.Len(response.Grants, 1)
	suite.Equal("root1", response.Grants[0].TargetOUID)
	suite.Equal(1, response.TotalResults)
	suite.Equal(1, response.StartIndex)
	suite.Equal(1, response.Count)
	// A single page that holds everything needs no navigation links.
	suite.Empty(response.Links)
}

// TestHandleRoleGrantsGetRequest_Paginated proves the query parameters reach the service and
// that a partial page advertises the total and a next link.
func (suite *RoleHandlerTestSuite) TestHandleRoleGrantsGetRequest_Paginated() {
	fakeSharing := &fakeSharingService{
		listGrantsPageFunc: func(
			_ context.Context, _ sharing.ResourceType, _ string, limit, offset int,
		) (*sharing.GrantPage, *tidcommon.ServiceError) {
			suite.Equal(2, limit)
			suite.Equal(2, offset)
			return &sharing.GrantPage{
				Grants: []sharing.Grant{
					{
						ID: "grant3", Stage: sharing.StageShare,
						TargetScope: sharing.TargetScopeRoot, TargetOUID: "root3",
					},
					{
						ID: "grant4", Stage: sharing.StageShare,
						TargetScope: sharing.TargetScopeRoot, TargetOUID: "root4",
					},
				},
				TotalResults: 5,
			}, nil
		},
	}
	suite.handler = newRoleHandler(suite.mockService, suite.mockAssignmentService, fakeSharing)

	req := httptest.NewRequest(http.MethodGet, "/roles/role1/grants?limit=2&offset=2", nil)
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleGrantsGetRequest(w, req)

	suite.Equal(http.StatusOK, w.Code)
	var response GrantListResponse
	suite.NoError(json.NewDecoder(w.Body).Decode(&response))
	suite.Equal(5, response.TotalResults)
	suite.Equal(3, response.StartIndex)
	suite.Equal(2, response.Count)
	suite.Len(response.Grants, 2)

	rels := make([]string, 0, len(response.Links))
	for _, l := range response.Links {
		rels = append(rels, l.Rel)
		suite.Contains(l.Href, "/roles/role1/grants")
	}
	suite.ElementsMatch([]string{"first", "prev", "next", "last"}, rels)
}

// TestHandleRoleGrantsGetRequest_InvalidPagination proves a bad limit is rejected with the
// same error the other paginated role endpoints use, before the sharing service is consulted.
func (suite *RoleHandlerTestSuite) TestHandleRoleGrantsGetRequest_InvalidPagination() {
	for _, tc := range []struct {
		name, query, expectedCode string
	}{
		{"non-numeric limit", "?limit=abc", ErrorInvalidLimit.Code},
		{"limit above max", "?limit=1000", ErrorInvalidLimit.Code},
		{"zero limit is defaulted, negative offset rejected", "?offset=-1", ErrorInvalidOffset.Code},
	} {
		suite.Run(tc.name, func() {
			// No func set on the fake: reaching the service at all would panic.
			suite.handler = newRoleHandler(suite.mockService, suite.mockAssignmentService, &fakeSharingService{})

			req := httptest.NewRequest(http.MethodGet, "/roles/role1/grants"+tc.query, nil)
			req.SetPathValue("id", "role1")
			w := httptest.NewRecorder()

			suite.handler.HandleRoleGrantsGetRequest(w, req)

			suite.Equal(http.StatusBadRequest, w.Code)
			var errResp map[string]interface{}
			suite.NoError(json.NewDecoder(w.Body).Decode(&errResp))
			suite.Equal(tc.expectedCode, errResp["code"])
		})
	}
}

func (suite *RoleHandlerTestSuite) TestHandleRoleGrantsGetRequest_Error() {
	fakeSharing := &fakeSharingService{
		listGrantsPageFunc: func(
			_ context.Context, _ sharing.ResourceType, _ string, _, _ int,
		) (*sharing.GrantPage, *tidcommon.ServiceError) {
			return nil, &tidcommon.InternalServerError
		},
	}
	suite.handler = newRoleHandler(suite.mockService, suite.mockAssignmentService, fakeSharing)

	req := httptest.NewRequest(http.MethodGet, "/roles/role1/grants", nil)
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleGrantsGetRequest(w, req)

	suite.Equal(http.StatusInternalServerError, w.Code)
}

// HandleRoleUnshareRequest Tests

func (suite *RoleHandlerTestSuite) TestHandleRoleUnshareRequest_Success() {
	fakeSharing := &fakeSharingService{
		unshareFunc: func(_ context.Context, grantID string) *tidcommon.ServiceError {
			suite.Equal("grant1", grantID)
			return nil
		},
	}
	suite.handler = newRoleHandler(suite.mockService, suite.mockAssignmentService, fakeSharing)

	req := httptest.NewRequest(http.MethodDelete, "/roles/role1/grants/grant1", nil)
	req.SetPathValue("id", "role1")
	req.SetPathValue("grantId", "grant1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleUnshareRequest(w, req)

	suite.Equal(http.StatusNoContent, w.Code)
}

func (suite *RoleHandlerTestSuite) TestHandleRoleUnshareRequest_NotFound() {
	fakeSharing := &fakeSharingService{
		unshareFunc: func(_ context.Context, _ string) *tidcommon.ServiceError {
			return &sharing.ErrorGrantNotFound
		},
	}
	suite.handler = newRoleHandler(suite.mockService, suite.mockAssignmentService, fakeSharing)

	req := httptest.NewRequest(http.MethodDelete, "/roles/role1/grants/missing", nil)
	req.SetPathValue("id", "role1")
	req.SetPathValue("grantId", "missing")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleUnshareRequest(w, req)

	suite.Equal(http.StatusNotFound, w.Code)
}

// HandleRoleEditableFieldsGetRequest Tests

func (suite *RoleHandlerTestSuite) TestHandleRoleEditableFieldsGetRequest_Success() {
	suite.mockAssignmentService.On("GetEditableFields", mock.Anything, "role1", "ou1").
		Return([]string{"assignments.user", "assignments.group"}, nil)

	req := httptest.NewRequest(http.MethodGet, "/roles/role1/editable-fields?ouId=ou1", nil)
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleEditableFieldsGetRequest(w, req)

	suite.Equal(http.StatusOK, w.Code)
	var response EditableFieldsResponse
	suite.NoError(json.NewDecoder(w.Body).Decode(&response))
	suite.ElementsMatch([]string{"assignments.user", "assignments.group"}, response.Fields)
}

func (suite *RoleHandlerTestSuite) TestHandleRoleEditableFieldsGetRequest_DefaultsOUIDToEmpty() {
	suite.mockAssignmentService.On("GetEditableFields", mock.Anything, "role1", "").
		Return([]string{"assignments"}, nil)

	req := httptest.NewRequest(http.MethodGet, "/roles/role1/editable-fields", nil)
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleEditableFieldsGetRequest(w, req)

	suite.Equal(http.StatusOK, w.Code)
}

func (suite *RoleHandlerTestSuite) TestHandleRoleEditableFieldsGetRequest_ServiceError() {
	suite.mockAssignmentService.On("GetEditableFields", mock.Anything, "role1", "ou1").
		Return(nil, &ErrorRoleOutsideOwnOUScope)

	req := httptest.NewRequest(http.MethodGet, "/roles/role1/editable-fields?ouId=ou1", nil)
	req.SetPathValue("id", "role1")
	w := httptest.NewRecorder()

	suite.handler.HandleRoleEditableFieldsGetRequest(w, req)

	suite.Equal(http.StatusForbidden, w.Code)
}
