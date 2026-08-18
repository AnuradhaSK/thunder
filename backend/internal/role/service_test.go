// Copyright 2025 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"context"
	"errors"
	"os"
	"testing"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/group"
	oupkg "github.com/thunder-id/thunderid/internal/ou"
	"github.com/thunder-id/thunderid/internal/sharing"
	"github.com/thunder-id/thunderid/internal/system/config"
	serverconst "github.com/thunder-id/thunderid/internal/system/constants"
	"github.com/thunder-id/thunderid/internal/system/resourcedependency"
	"github.com/thunder-id/thunderid/internal/system/security"
	"github.com/thunder-id/thunderid/internal/system/sysauthz"
	"github.com/thunder-id/thunderid/internal/system/utils"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
	"github.com/thunder-id/thunderid/tests/mocks/entitymock"
	"github.com/thunder-id/thunderid/tests/mocks/entitytypemock"
	"github.com/thunder-id/thunderid/tests/mocks/groupmock"
	"github.com/thunder-id/thunderid/tests/mocks/oumock"
	"github.com/thunder-id/thunderid/tests/mocks/resourcemock"
	"github.com/thunder-id/thunderid/tests/mocks/sysauthzmock"
)

const (
	testUserID1 = "user1"
	testUserID2 = "user2"
)

func TestMain(m *testing.M) {
	security.InitSystemPermissions("")
	os.Exit(m.Run())
}

// testRootContext returns a context carrying the root system OAuth scope, so tests that predate
// the system:roles OU-scoping checks exercise their intended behavior without needing every test
// to construct a specific caller OU — a root-scoped caller is always unrestricted, matching this
// package's pre-existing test expectations. Tests that specifically exercise own-OU-scope behavior
// build their own narrower context instead (see testOwnOUContext).
func testRootContext() context.Context {
	authCtx := security.NewSecurityContextForTest("test-subject", "test-ou", "test-token", []string{"system"}, nil)
	return security.WithSecurityContextTest(context.Background(), authCtx)
}

// testOwnOUContext returns a context carrying ouID as the caller's own OU claim, with no root
// permission — i.e. a system:roles-only caller confined to ouID.
func testOwnOUContext(ouID string) context.Context {
	authCtx := security.NewSecurityContextForTest("test-subject", ouID, "test-token", nil, nil)
	return security.WithSecurityContextTest(context.Background(), authCtx)
}

// fakeTransactioner is a light-weight test double to capture transaction usage.
type fakeTransactioner struct {
	transactCalls int
	err           error
}

func (f *fakeTransactioner) Transact(ctx context.Context, txFunc func(context.Context) error) error {
	f.transactCalls++
	if f.err != nil {
		return f.err
	}
	return txFunc(ctx)
}

// fakeSharingService is a light-weight test double for sharing.ServiceInterface. Existing tests
// build contexts with no OU claim, so the acting OU always resolves to the role's own OU and the
// sharing-checked path is never exercised; any unexpected call fails loudly rather than silently
// returning a zero value.
type fakeSharingService struct {
	isSharedFunc func(
		ctx context.Context, resourceType sharing.ResourceType, resourceID, ouID string,
	) (bool, *tidcommon.ServiceError)
	resolveEditabilityFunc func(
		ctx context.Context, resourceType sharing.ResourceType, resourceID, owningOUID, ouID, fieldKey string,
	) (bool, *tidcommon.ServiceError)
	resolveEditableFieldsFunc func(
		ctx context.Context, resourceType sharing.ResourceType, resourceID, owningOUID, ouID string,
	) ([]string, *tidcommon.ServiceError)
	listSharedResourceIDsFunc func(
		ctx context.Context, resourceType sharing.ResourceType, ouID string,
	) ([]string, *tidcommon.ServiceError)
	shareFunc func(
		ctx context.Context, resourceType sharing.ResourceType, resourceID, owningOUID, actingOUID string,
		policy sharing.SharePolicy,
	) ([]sharing.Grant, *tidcommon.ServiceError)
	shareDeclarativeFunc func(
		ctx context.Context, resourceType sharing.ResourceType, resourceID, owningOUID, actingOUID string,
		policy sharing.SharePolicy,
	) ([]sharing.Grant, *tidcommon.ServiceError)
	unshareFunc    func(ctx context.Context, grantID string) *tidcommon.ServiceError
	listGrantsFunc func(
		ctx context.Context, resourceType sharing.ResourceType, resourceID string,
	) ([]sharing.Grant, *tidcommon.ServiceError)
	listGrantsPageFunc func(
		ctx context.Context, resourceType sharing.ResourceType, resourceID string, limit, offset int,
	) (*sharing.GrantPage, *tidcommon.ServiceError)
	exportGrantsFunc func(
		ctx context.Context, resourceType sharing.ResourceType, resourceID string,
	) ([]sharing.ReplayableGrant, *tidcommon.ServiceError)
	requireOwnershipFunc func(
		ctx context.Context, resourceType sharing.ResourceType, owningOUID string,
	) *tidcommon.ServiceError
	requireOwnershipForDeletionFunc func(
		ctx context.Context, resourceType sharing.ResourceType, owningOUID string,
	) *tidcommon.ServiceError
}

// RegisterResourceType is a no-op: Initialize always calls this once during wiring to onboard
// role onto the sharing framework, so unlike the other methods here it's an expected call in
// every test that exercises Initialize, not just tests specifically targeting sharing behavior.
func (f *fakeSharingService) RegisterResourceType(_ sharing.ResourceTypeDeclaration) {}

func (f *fakeSharingService) Share(
	ctx context.Context, resourceType sharing.ResourceType, resourceID, owningOUID, actingOUID string,
	policy sharing.SharePolicy,
) ([]sharing.Grant, *tidcommon.ServiceError) {
	if f.shareFunc != nil {
		return f.shareFunc(ctx, resourceType, resourceID, owningOUID, actingOUID, policy)
	}
	panic("fakeSharingService: unexpected call to Share")
}

func (f *fakeSharingService) ShareDeclarative(
	ctx context.Context, resourceType sharing.ResourceType, resourceID, owningOUID, actingOUID string,
	policy sharing.SharePolicy,
) ([]sharing.Grant, *tidcommon.ServiceError) {
	if f.shareDeclarativeFunc != nil {
		return f.shareDeclarativeFunc(ctx, resourceType, resourceID, owningOUID, actingOUID, policy)
	}
	panic("fakeSharingService: unexpected call to ShareDeclarative")
}

func (f *fakeSharingService) Unshare(ctx context.Context, grantID string) *tidcommon.ServiceError {
	if f.unshareFunc != nil {
		return f.unshareFunc(ctx, grantID)
	}
	panic("fakeSharingService: unexpected call to Unshare")
}

func (f *fakeSharingService) ListGrants(
	ctx context.Context, resourceType sharing.ResourceType, resourceID string,
) ([]sharing.Grant, *tidcommon.ServiceError) {
	if f.listGrantsFunc != nil {
		return f.listGrantsFunc(ctx, resourceType, resourceID)
	}
	panic("fakeSharingService: unexpected call to ListGrants")
}

func (f *fakeSharingService) ListGrantsPage(
	ctx context.Context, resourceType sharing.ResourceType, resourceID string, limit, offset int,
) (*sharing.GrantPage, *tidcommon.ServiceError) {
	if f.listGrantsPageFunc != nil {
		return f.listGrantsPageFunc(ctx, resourceType, resourceID, limit, offset)
	}
	panic("fakeSharingService: unexpected call to ListGrantsPage")
}

func (f *fakeSharingService) ExportGrants(
	ctx context.Context, resourceType sharing.ResourceType, resourceID string,
) ([]sharing.ReplayableGrant, *tidcommon.ServiceError) {
	if f.exportGrantsFunc != nil {
		return f.exportGrantsFunc(ctx, resourceType, resourceID)
	}
	panic("fakeSharingService: unexpected call to ExportGrants")
}

func (f *fakeSharingService) IsShared(
	ctx context.Context, resourceType sharing.ResourceType, resourceID, ouID string,
) (bool, *tidcommon.ServiceError) {
	if f.isSharedFunc != nil {
		return f.isSharedFunc(ctx, resourceType, resourceID, ouID)
	}
	panic("fakeSharingService: unexpected call to IsShared")
}

func (f *fakeSharingService) ListSharedResourceIDs(
	ctx context.Context, resourceType sharing.ResourceType, ouID string,
) ([]string, *tidcommon.ServiceError) {
	if f.listSharedResourceIDsFunc != nil {
		return f.listSharedResourceIDsFunc(ctx, resourceType, ouID)
	}
	panic("fakeSharingService: unexpected call to ListSharedResourceIDs")
}

func (f *fakeSharingService) ResolveEditability(
	ctx context.Context, resourceType sharing.ResourceType, resourceID, owningOUID, ouID, fieldKey string,
) (bool, *tidcommon.ServiceError) {
	if f.resolveEditabilityFunc != nil {
		return f.resolveEditabilityFunc(ctx, resourceType, resourceID, owningOUID, ouID, fieldKey)
	}
	panic("fakeSharingService: unexpected call to ResolveEditability")
}

func (f *fakeSharingService) RequireOwnership(
	ctx context.Context, resourceType sharing.ResourceType, owningOUID string,
) *tidcommon.ServiceError {
	if f.requireOwnershipFunc != nil {
		return f.requireOwnershipFunc(ctx, resourceType, owningOUID)
	}
	panic("fakeSharingService: unexpected call to RequireOwnership")
}

func (f *fakeSharingService) RequireOwnershipForDeletion(
	ctx context.Context, resourceType sharing.ResourceType, owningOUID string,
) *tidcommon.ServiceError {
	if f.requireOwnershipForDeletionFunc != nil {
		return f.requireOwnershipForDeletionFunc(ctx, resourceType, owningOUID)
	}
	panic("fakeSharingService: unexpected call to RequireOwnershipForDeletion")
}

func (f *fakeSharingService) ResolveEditableFields(
	ctx context.Context, resourceType sharing.ResourceType, resourceID, owningOUID, ouID string,
) ([]string, *tidcommon.ServiceError) {
	if f.resolveEditableFieldsFunc != nil {
		return f.resolveEditableFieldsFunc(ctx, resourceType, resourceID, owningOUID, ouID)
	}
	panic("fakeSharingService: unexpected call to ResolveEditableFields")
}

// Test Suite
type RoleServiceTestSuite struct {
	suite.Suite
	mockStore             *roleStoreInterfaceMock
	mockEntityService     *entitymock.EntityServiceInterfaceMock
	mockGroupService      *groupmock.GroupServiceInterfaceMock
	mockOUService         *oumock.OrganizationUnitServiceInterfaceMock
	mockResourceService   *resourcemock.ResourceServiceInterfaceMock
	mockEntityTypeService *entitytypemock.EntityTypeServiceInterfaceMock
	sharingService        *fakeSharingService
	transactioner         *fakeTransactioner
	service               RoleServiceInterface
}

func TestRoleServiceTestSuite(t *testing.T) {
	suite.Run(t, new(RoleServiceTestSuite))
}

func (suite *RoleServiceTestSuite) SetupTest() {
	// Initialize config runtime with default values
	testConfig := &config.Config{
		DeclarativeResources: config.DeclarativeResources{
			Enabled: false,
		},
	}
	config.ResetServerRuntime()
	err := config.InitializeServerRuntime("/tmp/test", testConfig)
	if err != nil {
		suite.Fail("Failed to initialize runtime", err)
	}

	suite.mockStore = newRoleStoreInterfaceMock(suite.T())
	suite.mockEntityService = entitymock.NewEntityServiceInterfaceMock(suite.T())
	suite.mockGroupService = groupmock.NewGroupServiceInterfaceMock(suite.T())
	suite.mockOUService = oumock.NewOrganizationUnitServiceInterfaceMock(suite.T())
	suite.mockResourceService = resourcemock.NewResourceServiceInterfaceMock(suite.T())
	suite.mockEntityTypeService = entitytypemock.NewEntityTypeServiceInterfaceMock(suite.T())
	suite.sharingService = &fakeSharingService{
		// Permissive default so the many Create/Update/Delete tests that don't care about the
		// ownership check keep passing unchanged; tests that do care override this field directly.
		requireOwnershipFunc: func(
			_ context.Context, _ sharing.ResourceType, _ string,
		) *tidcommon.ServiceError {
			return nil
		},
		requireOwnershipForDeletionFunc: func(
			_ context.Context, _ sharing.ResourceType, _ string,
		) *tidcommon.ServiceError {
			return nil
		},
	}
	suite.transactioner = &fakeTransactioner{}
	suite.service = newRoleService(
		suite.mockStore,
		suite.mockEntityService,
		suite.mockGroupService,
		suite.mockOUService,
		suite.mockResourceService,
		suite.sharingService,
		suite.transactioner,
		newAllowAllRoleAuthz(suite.T()),
	)
}

// TearDownTest cleans up after each test
func (suite *RoleServiceTestSuite) TearDownTest() {
	config.ResetServerRuntime()
}

// GetRoleList Tests
func (suite *RoleServiceTestSuite) TestGetRoleList_Success() {
	expectedRoles := []Role{
		{ID: "role1", Name: "Admin", OUID: "ou1"},
		{ID: "role2", Name: "User", OUID: "ou1"},
	}

	suite.mockStore.On("GetRoleListCount", mock.Anything).Return(2, nil)
	suite.mockStore.On("GetRoleList", mock.Anything, 10, 0).Return(expectedRoles, nil)
	suite.mockOUService.On("GetOrganizationUnitHandlesByIDs", mock.Anything,
		[]string{"ou1"}).Return(map[string]string{"ou1": "default"}, nil)

	result, err := suite.service.GetRoleList(testRootContext(), 10, 0)

	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal(2, result.TotalResults)
	suite.Equal(2, result.Count)
	suite.Equal(1, result.StartIndex)
	suite.Equal(2, len(result.Roles))
	suite.Equal("role1", result.Roles[0].ID)
	suite.Equal("Admin", result.Roles[0].Name)
	suite.Equal("default", result.Roles[0].OUHandle)
	suite.Equal("role2", result.Roles[1].ID)
	suite.Equal("User", result.Roles[1].Name)
	suite.Equal("default", result.Roles[1].OUHandle)
}

func (suite *RoleServiceTestSuite) TestGetRoleList_InvalidPagination() {
	testCases := []struct {
		name    string
		limit   int
		offset  int
		errCode string
	}{
		{"InvalidLimit_Zero", 0, 0, ErrorInvalidLimit.Code},
		{"InvalidLimit_TooLarge", serverconst.MaxPageSize + 1, 0, ErrorInvalidLimit.Code},
		{"InvalidOffset_Negative", 10, -1, ErrorInvalidOffset.Code},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			result, err := suite.service.GetRoleList(testRootContext(), tc.limit, tc.offset)
			suite.Nil(result)
			suite.NotNil(err)
			suite.Equal(tc.errCode, err.Code)
		})
	}
}

func (suite *RoleServiceTestSuite) TestGetRoleList_StoreErrors() {
	testCases := []struct {
		name      string
		mockSetup func()
	}{
		{
			name: "CountError",
			mockSetup: func() {
				suite.mockStore.On("GetRoleListCount", mock.Anything).Return(0, errors.New("database error")).Once()
			},
		},
		{
			name: "GetListError",
			mockSetup: func() {
				suite.mockStore.On("GetRoleListCount", mock.Anything).Return(10, nil).Once()
				suite.mockStore.On("GetRoleList", mock.Anything,
					10, 0).
					Return([]Role{}, errors.New("database error")).Once()
			},
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			tc.mockSetup()

			result, err := suite.service.GetRoleList(testRootContext(), 10, 0)

			suite.Nil(result)
			suite.NotNil(err)
			suite.Equal(tidcommon.InternalServerError.Code, err.Code)
		})
	}
}

func (suite *RoleServiceTestSuite) TestGetRoleList_OUHandlesError() {
	expectedRoles := []Role{
		{ID: "role1", Name: "Admin", OUID: "ou1"},
	}

	suite.mockStore.On("GetRoleListCount", mock.Anything).Return(1, nil)
	suite.mockStore.On("GetRoleList", mock.Anything, 10, 0).Return(expectedRoles, nil)
	suite.mockOUService.On("GetOrganizationUnitHandlesByIDs", mock.Anything,
		[]string{"ou1"}).Return(nil, &tidcommon.ServiceError{Code: "INTERNAL_ERROR"})

	result, err := suite.service.GetRoleList(testRootContext(), 10, 0)

	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal(1, result.Count)
	suite.Equal("role1", result.Roles[0].ID)
	suite.Equal("", result.Roles[0].OUHandle)
}

// GetRolesForOU Tests

func (suite *RoleServiceTestSuite) TestGetRolesForOU_MissingOUID() {
	result, err := suite.service.GetRolesForOU(testRootContext(), "", 10, 0)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(ErrorMissingOUIDParam.Code, err.Code)
}

func (suite *RoleServiceTestSuite) TestGetRolesForOU_InvalidPagination() {
	result, err := suite.service.GetRolesForOU(testRootContext(), "ou1", 0, -1)

	suite.Nil(result)
	suite.NotNil(err)
}

// TestGetRolesForOU_RejectsOutsideCallerOwnOU proves a system:roles-only caller (no root
// permission) may only list the OU its own token was issued for.
func (suite *RoleServiceTestSuite) TestGetRolesForOU_RejectsOutsideCallerOwnOU() {
	result, err := suite.service.GetRolesForOU(testOwnOUContext("ou1"), "ou2", 10, 0)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(ErrorRoleOutsideOwnOUScope.Code, err.Code)
	suite.mockStore.AssertNotCalled(suite.T(), "GetRoleListCountByOUID", mock.Anything, mock.Anything)
}

// TestGetRolesForOU_AllowsCallerOwnOU proves a system:roles-only caller can list its own OU.
func (suite *RoleServiceTestSuite) TestGetRolesForOU_AllowsCallerOwnOU() {
	owned := []Role{{ID: "role1", Name: "Admin", OUID: "ou1"}}
	suite.mockStore.On("GetRoleListCountByOUID", mock.Anything, "ou1").Return(1, nil)
	suite.mockStore.On("GetRoleListByOUID", mock.Anything, "ou1", 1, 0).Return(owned, nil)
	suite.sharingService.listSharedResourceIDsFunc = func(
		context.Context, sharing.ResourceType, string,
	) ([]string, *tidcommon.ServiceError) {
		return []string{}, nil
	}
	suite.mockOUService.On("GetOrganizationUnitHandlesByIDs", mock.Anything, []string{"ou1"}).
		Return(map[string]string{"ou1": "acme"}, nil)

	result, err := suite.service.GetRolesForOU(testOwnOUContext("ou1"), "ou1", 10, 0)

	suite.Nil(err)
	suite.Require().Len(result.Roles, 1)
}

func (suite *RoleServiceTestSuite) TestGetRolesForOU_OwnedOnly_Success() {
	owned := []Role{{ID: "role1", Name: "Admin", OUID: "ou1"}}

	suite.mockStore.On("GetRoleListCountByOUID", mock.Anything, "ou1").Return(1, nil)
	suite.mockStore.On("GetRoleListByOUID", mock.Anything, "ou1", 1, 0).Return(owned, nil)
	suite.sharingService.listSharedResourceIDsFunc = func(
		context.Context, sharing.ResourceType, string,
	) ([]string, *tidcommon.ServiceError) {
		return []string{}, nil
	}
	suite.mockOUService.On("GetOrganizationUnitHandlesByIDs", mock.Anything, []string{"ou1"}).
		Return(map[string]string{"ou1": "acme"}, nil)

	result, err := suite.service.GetRolesForOU(testRootContext(), "ou1", 10, 0)

	suite.Nil(err)
	suite.Require().Len(result.Roles, 1)
	suite.Equal(RoleOriginOwned, result.Roles[0].Origin)
	suite.Equal("acme", result.Roles[0].OUHandle)
	suite.Equal(1, result.TotalResults)
}

func (suite *RoleServiceTestSuite) TestGetRolesForOU_OwnedAndShared_Success() {
	owned := []Role{{ID: "role1", Name: "Admin", OUID: "ou1"}}

	suite.mockStore.On("GetRoleListCountByOUID", mock.Anything, "ou1").Return(1, nil)
	suite.mockStore.On("GetRoleListByOUID", mock.Anything, "ou1", 1, 0).Return(owned, nil)
	suite.sharingService.listSharedResourceIDsFunc = func(
		_ context.Context, resourceType sharing.ResourceType, ouID string,
	) ([]string, *tidcommon.ServiceError) {
		suite.Equal(roleSharingResourceType, resourceType)
		suite.Equal("ou1", ouID)
		return []string{"role2"}, nil
	}
	suite.mockStore.On("GetRole", mock.Anything, "role2").
		Return(RoleWithPermissions{ID: "role2", Name: "Viewer", OUID: "owner-ou"}, nil)
	suite.mockOUService.On("GetOrganizationUnitHandlesByIDs", mock.Anything, mock.MatchedBy(func(ids []string) bool {
		return len(ids) == 2
	})).Return(map[string]string{"ou1": "acme", "owner-ou": "globex"}, nil)

	result, err := suite.service.GetRolesForOU(testRootContext(), "ou1", 10, 0)

	suite.Nil(err)
	suite.Require().Len(result.Roles, 2)

	byID := map[string]RoleForOU{}
	for _, r := range result.Roles {
		byID[r.ID] = r
	}
	suite.Equal(RoleOriginOwned, byID["role1"].Origin)
	suite.Equal(RoleOriginShared, byID["role2"].Origin)
	suite.Equal("globex", byID["role2"].OUHandle, "shared role's core is resolved from its owning OU")
}

func (suite *RoleServiceTestSuite) TestGetRolesForOU_SkipsStaleSharedRole() {
	suite.mockStore.On("GetRoleListCountByOUID", mock.Anything, "ou1").Return(0, nil)
	suite.mockStore.On("GetRoleListByOUID", mock.Anything, "ou1", 0, 0).Return([]Role{}, nil)
	suite.sharingService.listSharedResourceIDsFunc = func(
		context.Context, sharing.ResourceType, string,
	) ([]string, *tidcommon.ServiceError) {
		return []string{"deleted-role"}, nil
	}
	suite.mockStore.On("GetRole", mock.Anything, "deleted-role").Return(RoleWithPermissions{}, ErrRoleNotFound)

	result, err := suite.service.GetRolesForOU(testRootContext(), "ou1", 10, 0)

	suite.Nil(err)
	suite.Empty(result.Roles, "a grant pointing at a since-deleted role should be skipped, not error")
}

func (suite *RoleServiceTestSuite) TestGetRolesForOU_SharingServiceError() {
	suite.mockStore.On("GetRoleListCountByOUID", mock.Anything, "ou1").Return(0, nil)
	suite.mockStore.On("GetRoleListByOUID", mock.Anything, "ou1", 0, 0).Return([]Role{}, nil)
	suite.sharingService.listSharedResourceIDsFunc = func(
		context.Context, sharing.ResourceType, string,
	) ([]string, *tidcommon.ServiceError) {
		return nil, &tidcommon.InternalServerError
	}

	result, err := suite.service.GetRolesForOU(testRootContext(), "ou1", 10, 0)

	suite.Nil(result)
	suite.NotNil(err)
}

func (suite *RoleServiceTestSuite) TestGetRolesForOU_CountStoreError() {
	suite.mockStore.On("GetRoleListCountByOUID", mock.Anything, "ou1").Return(0, errors.New("db error"))

	result, err := suite.service.GetRolesForOU(testRootContext(), "ou1", 10, 0)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

// CreateRole Tests
func (suite *RoleServiceTestSuite) TestCreateRole_Success() {
	request := RoleCreationDetail{
		Name:        "Test Role",
		Description: "Test Description",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1", "perm2"}}},
		Assignments: []RoleAssignment{
			{ID: testUserID1, Type: AssigneeTypeUser},
		},
	}

	ou := providers.OrganizationUnit{ID: "ou1", Name: "Test OU", Handle: "default"}
	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"perm1", "perm2"}).Return([]string{}, nil)
	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything,
		[]string{testUserID1}).Return(
		[]providers.Entity{{ID: testUserID1, Category: providers.EntityCategoryUser}}, nil)
	suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "ou1").Return(ou, nil)
	suite.mockStore.On("CheckRoleNameExists", mock.Anything,
		"ou1", "Test Role").Return(false, nil)
	suite.mockStore.On("CreateRole", mock.Anything,
		mock.AnythingOfType("string"),
		mock.AnythingOfType("RoleCreationDetail")).Return(nil)

	result, err := suite.service.CreateRole(testRootContext(), request)

	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal("Test Role", result.Name)
	suite.Equal("Test Description", result.Description)
	suite.Equal("ou1", result.OUID)
	suite.Equal("default", result.OUHandle)
	suite.Equal(1, len(result.Permissions))
	suite.Equal(2, len(result.Permissions[0].Permissions))
	// Verify permission validation was called
	suite.mockResourceService.AssertCalled(suite.T(), "ValidatePermissions", mock.Anything,
		"rs1", []string{"perm1", "perm2"})
}

// TestCreateRole_WrapsOUServiceCallWithRuntimeContext proves the OU-existence lookup doesn't
// re-authorize a caller who already passed RequireOwnership above. A system:roles-only caller
// (testOwnOUContext, no root permission) holds no system:ou/system:ou:view permission at all; if
// this call weren't wrapped in a runtime context, the real internal/ou service would reject it as
// Unauthorized even though the caller legitimately owns the target OU, and CreateRole would 500.
func (suite *RoleServiceTestSuite) TestCreateRole_WrapsOUServiceCallWithRuntimeContext() {
	request := RoleCreationDetail{
		Name: "Test Role",
		OUID: "ou1",
	}

	ou := providers.OrganizationUnit{ID: "ou1", Name: "Test OU", Handle: "default"}
	suite.mockOUService.On("GetOrganizationUnit",
		mock.MatchedBy(security.IsRuntimeContext),
		"ou1").Return(ou, nil)
	suite.mockStore.On("CheckRoleNameExists", mock.Anything,
		"ou1", "Test Role").Return(false, nil)
	suite.mockStore.On("CreateRole", mock.Anything,
		mock.AnythingOfType("string"),
		mock.AnythingOfType("RoleCreationDetail")).Return(nil)

	result, err := suite.service.CreateRole(testOwnOUContext("ou1"), request)

	suite.Nil(err)
	suite.NotNil(result)
}

func (suite *RoleServiceTestSuite) TestCreateRole_ValidationErrors() {
	testCases := []struct {
		name    string
		request RoleCreationDetail
		errCode string
	}{
		{
			name: "MissingName",
			request: RoleCreationDetail{
				OUID: "ou1",
				Permissions: []ResourcePermissions{{
					ResourceServerID: "rs1",
					Permissions:      []string{"perm1"},
				}},
			},
			errCode: ErrorInvalidRequestFormat.Code,
		},
		{
			name: "MissingOrgUnit",
			request: RoleCreationDetail{
				Name: "Role",
				Permissions: []ResourcePermissions{{
					ResourceServerID: "rs1",
					Permissions:      []string{"perm1"},
				}},
			},
			errCode: ErrorInvalidRequestFormat.Code,
		},
		{
			name: "InvalidAssignmentType",
			request: RoleCreationDetail{
				Name:        "Role",
				OUID:        "ou1",
				Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
				Assignments: []RoleAssignment{{ID: testUserID1, Type: "invalid"}},
			},
			errCode: ErrorInvalidAssigneeType.Code,
		},
		{
			name: "EmptyAssignmentID",
			request: RoleCreationDetail{
				Name:        "Role",
				OUID:        "ou1",
				Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
				Assignments: []RoleAssignment{{ID: "", Type: AssigneeTypeUser}},
			},
			errCode: ErrorInvalidRequestFormat.Code,
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			result, err := suite.service.CreateRole(testRootContext(), tc.request)
			suite.Nil(result)
			suite.NotNil(err)
			suite.Equal(tc.errCode, err.Code)
		})
	}
}

func (suite *RoleServiceTestSuite) TestCreateRole_PermissionValidationErrors() {
	testCases := []struct {
		name          string
		request       RoleCreationDetail
		setupMocks    func()
		expectedError *tidcommon.ServiceError
	}{
		{
			name: "InvalidPermissions",
			request: RoleCreationDetail{
				Name:        "Test Role",
				OUID:        "ou1",
				Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
			},
			setupMocks: func() {
				ou := providers.OrganizationUnit{ID: "ou1"}
				suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "ou1").Return(ou, nil).Once()
				suite.mockResourceService.On("ValidatePermissions", mock.Anything,
					"rs1", []string{"perm1"}).
					Return([]string{"perm1"}, nil).Once()
			},
			expectedError: &ErrorInvalidPermissions,
		},
		{
			name: "PermissionValidationServiceError",
			request: RoleCreationDetail{
				Name:        "Test Role",
				OUID:        "ou1",
				Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
			},
			setupMocks: func() {
				ou := providers.OrganizationUnit{ID: "ou1"}
				suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "ou1").Return(ou, nil).Once()
				suite.mockResourceService.On("ValidatePermissions", mock.Anything,
					"rs1", []string{"perm1"}).
					Return([]string{}, &tidcommon.ServiceError{Code: "INTERNAL_ERROR"}).Once()
			},
			expectedError: &tidcommon.InternalServerError,
		},
		{
			name: "EmptyResourceServerID",
			request: RoleCreationDetail{
				Name:        "Test Role",
				OUID:        "ou1",
				Permissions: []ResourcePermissions{{ResourceServerID: "", Permissions: []string{"perm1"}}},
			},
			setupMocks: func() {
				ou := providers.OrganizationUnit{ID: "ou1"}
				suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "ou1").Return(ou, nil).Once()
				// Resource service should not be called for empty resource server ID
			},
			expectedError: &ErrorInvalidPermissions,
		},
		{
			name: "EmptyPermissionsArray",
			request: RoleCreationDetail{
				Name:        "Test Role",
				Description: "Test Description",
				OUID:        "ou1",
				Permissions: []ResourcePermissions{},
			},
			setupMocks: func() {
				ou := providers.OrganizationUnit{ID: "ou1"}
				suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "ou1").Return(ou, nil).Once()
				suite.mockStore.On("CheckRoleNameExists", mock.Anything,
					"ou1", "Test Role").Return(false, nil).Once()
				suite.mockStore.On("CreateRole", mock.Anything,
					mock.AnythingOfType("string"),
					mock.AnythingOfType("RoleCreationDetail")).Return(nil).Once()
				// Resource service should NOT be called for empty permissions
			},
			expectedError: nil, // Success case
		},
		{
			name: "MultipleResourceServers",
			request: RoleCreationDetail{
				Name:        "Test Role",
				Description: "Test Description",
				OUID:        "ou1",
				Permissions: []ResourcePermissions{
					{ResourceServerID: "rs1", Permissions: []string{"perm1"}},
					{ResourceServerID: "rs2", Permissions: []string{"perm2"}},
				},
			},
			setupMocks: func() {
				ou := providers.OrganizationUnit{ID: "ou1"}
				suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "ou1").Return(ou, nil).Once()
				suite.mockResourceService.On("ValidatePermissions", mock.Anything,
					"rs1", []string{"perm1"}).
					Return([]string{}, nil).Once()
				suite.mockResourceService.On("ValidatePermissions", mock.Anything,
					"rs2", []string{"perm2"}).
					Return([]string{}, nil).Once()
				suite.mockStore.On("CheckRoleNameExists", mock.Anything,
					"ou1", "Test Role").Return(false, nil).Once()
				suite.mockStore.On("CreateRole", mock.Anything,
					mock.AnythingOfType("string"),
					mock.AnythingOfType("RoleCreationDetail")).Return(nil).Once()
			},
			expectedError: nil, // Success case
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			// Setup fresh mocks for this test case
			suite.SetupTest()
			tc.setupMocks()

			result, err := suite.service.CreateRole(testRootContext(), tc.request)

			if tc.expectedError != nil {
				suite.Nil(result)
				suite.NotNil(err)
				suite.Equal(tc.expectedError.Code, err.Code)
			} else {
				suite.Nil(err)
				suite.NotNil(result)
			}
		})
	}
}

func (suite *RoleServiceTestSuite) TestCreateRole_OrganizationUnitNotFound() {
	request := RoleCreationDetail{
		Name:        "Test Role",
		OUID:        "nonexistent",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
	}

	suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "nonexistent").
		Return(providers.OrganizationUnit{}, &oupkg.ErrorOrganizationUnitNotFound)

	result, err := suite.service.CreateRole(testRootContext(), request)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(ErrorOrganizationUnitNotFound.Code, err.Code)
}

func (suite *RoleServiceTestSuite) TestCreateRole_InvalidUserID() {
	request := RoleCreationDetail{
		Name:        "Test Role",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
		Assignments: []RoleAssignment{{ID: "invalid_user", Type: AssigneeTypeUser}},
	}

	ou := providers.OrganizationUnit{ID: "ou1"}
	suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "ou1").Return(ou, nil)
	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"perm1"}).Return([]string{}, nil)
	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything,
		[]string{"invalid_user"}).
		Return([]providers.Entity{}, nil)

	result, err := suite.service.CreateRole(testRootContext(), request)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(ErrorInvalidAssignmentID.Code, err.Code)
}

func (suite *RoleServiceTestSuite) TestCreateRole_InvalidGroupID() {
	request := RoleCreationDetail{
		Name:        "Test Role",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
		Assignments: []RoleAssignment{{ID: "invalid_group", Type: AssigneeTypeGroup}},
	}

	ou := providers.OrganizationUnit{ID: "ou1"}
	suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "ou1").Return(ou, nil)
	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"perm1"}).Return([]string{}, nil)
	suite.mockGroupService.On("ValidateGroupIDs", mock.Anything,
		[]string{"invalid_group"}).
		Return(&group.ErrorInvalidGroupMemberID)

	result, err := suite.service.CreateRole(testRootContext(), request)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(ErrorInvalidAssignmentID.Code, err.Code)
}

func (suite *RoleServiceTestSuite) TestCreateRole_StoreError() {
	request := RoleCreationDetail{
		Name:        "Test Role",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
	}

	ou := providers.OrganizationUnit{ID: "ou1"}
	suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "ou1").Return(ou, nil)
	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"perm1"}).Return([]string{}, nil)
	suite.mockStore.On("CheckRoleNameExists", mock.Anything,
		"ou1", "Test Role").Return(false, nil)
	suite.mockStore.On("CreateRole", mock.Anything,
		mock.AnythingOfType("string"),
		mock.AnythingOfType("RoleCreationDetail")).Return(errors.New("database error"))

	result, err := suite.service.CreateRole(testRootContext(), request)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

func (suite *RoleServiceTestSuite) TestCreateRole_NameConflict() {
	request := RoleCreationDetail{
		Name:        "Test Role",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
	}

	ou := providers.OrganizationUnit{ID: "ou1"}
	suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "ou1").Return(ou, nil)
	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"perm1"}).Return([]string{}, nil)
	suite.mockStore.On("CheckRoleNameExists", mock.Anything,
		"ou1", "Test Role").Return(true, nil)

	result, err := suite.service.CreateRole(testRootContext(), request)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(ErrorRoleNameConflict.Code, err.Code)
}

func (suite *RoleServiceTestSuite) TestCreateRole_CheckNameExistsError() {
	request := RoleCreationDetail{
		Name:        "Test Role",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
	}

	ou := providers.OrganizationUnit{ID: "ou1"}
	suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "ou1").Return(ou, nil)
	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"perm1"}).Return([]string{}, nil)
	suite.mockStore.On("CheckRoleNameExists", mock.Anything,
		"ou1", "Test Role").
		Return(false, errors.New("database error"))

	result, err := suite.service.CreateRole(testRootContext(), request)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

// CreateRole Declarative Mode Tests
func (suite *RoleServiceTestSuite) TestCreateRole_DeclarativeMode_Denied() {
	// Setup declarative-only mode
	testConfig := &config.Config{
		DeclarativeResources: config.DeclarativeResources{
			Enabled: true,
		},
		Role: config.RoleConfig{
			Store: "declarative",
		},
	}
	config.ResetServerRuntime()
	initErr := config.InitializeServerRuntime("/tmp/test", testConfig)
	if initErr != nil {
		suite.Fail("Failed to initialize runtime", initErr)
	}
	defer config.ResetServerRuntime()

	request := RoleCreationDetail{
		Name: "Test Role",
		OUID: "ou1",
	}

	result, err := suite.service.CreateRole(testRootContext(), request)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(ErrorDeclarativeModeCreateNotAllowed.Code, err.Code)
}

// TestCreateRole_RejectsWhenCallerDoesNotOwnRequestedOU proves core config (here: the very act of
// claiming ownership for a new role) is gated by sharing.RequireOwnership before any store access
// — a caller may only create a role owned by its own OU, unless unrestricted.
// TestCreateRole_RejectsWhenCallerDoesNotOwnRequestedOU proves a caller naming an ouId outside its
// own OU is rejected with ROL-1023 (OU-reach), not SHR-1007 (core-config ownership) — there is no
// existing role yet for SHR-1007's "core config" framing to apply to, so this is gated by
// requireOwnOUScope, the same reach check used for read/list/assignment paths, not
// sharing.RequireOwnership.
func (suite *RoleServiceTestSuite) TestCreateRole_RejectsWhenCallerDoesNotOwnRequestedOU() {
	request := RoleCreationDetail{
		Name: "Test Role",
		OUID: "ou1",
	}

	result, err := suite.service.CreateRole(testOwnOUContext("caller-ou"), request)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(ErrorRoleOutsideOwnOUScope.Code, err.Code)
	suite.mockOUService.AssertNotCalled(suite.T(), "GetOrganizationUnit", mock.Anything, mock.Anything)
}

func (suite *RoleServiceTestSuite) TestUpdateRole_DeclarativeMode_Denied() {
	// Setup declarative-only mode
	testConfig := &config.Config{
		DeclarativeResources: config.DeclarativeResources{
			Enabled: true,
		},
		Role: config.RoleConfig{
			Store: "declarative",
		},
	}
	config.ResetServerRuntime()
	initErr := config.InitializeServerRuntime("/tmp/test", testConfig)
	if initErr != nil {
		suite.Fail("Failed to initialize runtime", initErr)
	}
	defer config.ResetServerRuntime()

	request := RoleUpdateDetail{
		Name:        "Updated Role",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
	}

	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"perm1"}).Return([]string{}, nil)
	suite.mockStore.On("GetRole", mock.Anything, "role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockStore.On("IsRoleDeclarative", mock.Anything, "role1").Return(true, nil)

	result, err := suite.service.UpdateRoleWithPermissions(testRootContext(), "role1", request)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(ErrorImmutableRole.Code, err.Code)
}

// GetRoleWithPermissions Tests
func (suite *RoleServiceTestSuite) TestGetRole_Success() {
	expectedRole := RoleWithPermissions{
		ID:          "role1",
		Name:        "Admin",
		Description: "Administrator role",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1", "perm2"}}},
	}

	suite.mockStore.On("GetRole", mock.Anything, "role1").Return(expectedRole, nil)
	suite.mockOUService.On("GetOrganizationUnit", mock.Anything,
		"ou1").Return(providers.OrganizationUnit{ID: "ou1", Handle: "default"}, nil)

	result, err := suite.service.GetRoleWithPermissions(testRootContext(), "role1")

	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal(expectedRole.ID, result.ID)
	suite.Equal(expectedRole.Name, result.Name)
	suite.Equal("default", result.OUHandle)
}

// TestGetRole_AllowsCallerOwnOU proves a system:roles-only caller can view a role owned by its
// own OU.
func (suite *RoleServiceTestSuite) TestGetRole_AllowsCallerOwnOU() {
	expectedRole := RoleWithPermissions{ID: "role1", Name: "Admin", OUID: "ou1"}
	suite.mockStore.On("GetRole", mock.Anything, "role1").Return(expectedRole, nil)
	suite.mockOUService.On("GetOrganizationUnit", mock.Anything,
		"ou1").Return(providers.OrganizationUnit{ID: "ou1", Handle: "default"}, nil)

	result, err := suite.service.GetRoleWithPermissions(testOwnOUContext("ou1"), "role1")

	suite.Nil(err)
	suite.NotNil(result)
}

// TestGetRole_RejectsOutsideCallerOwnOU_NotShared proves a system:roles-only caller cannot view a
// role owned by a different OU when it hasn't been shared to the caller's own OU.
func (suite *RoleServiceTestSuite) TestGetRole_RejectsOutsideCallerOwnOU_NotShared() {
	expectedRole := RoleWithPermissions{ID: "role1", Name: "Admin", OUID: "ou1"}
	suite.mockStore.On("GetRole", mock.Anything, "role1").Return(expectedRole, nil)
	suite.sharingService.isSharedFunc = func(
		_ context.Context, resourceType sharing.ResourceType, resourceID, ouID string,
	) (bool, *tidcommon.ServiceError) {
		suite.Equal(roleSharingResourceType, resourceType)
		suite.Equal("role1", resourceID)
		suite.Equal("sharee-ou", ouID)
		return false, nil
	}

	result, err := suite.service.GetRoleWithPermissions(testOwnOUContext("sharee-ou"), "role1")

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(ErrorRoleOutsideOwnOUScope.Code, err.Code)
	suite.mockOUService.AssertNotCalled(suite.T(), "GetOrganizationUnit", mock.Anything, mock.Anything)
}

// TestGetRole_AllowsOutsideCallerOwnOU_Shared proves a system:roles-only caller can still view a
// role owned by a different OU when it has genuinely been shared to the caller's own OU.
// TestGetRole_AllowsOutsideCallerOwnOU_Shared also proves the OU-handle lookup below the
// shared-fallback doesn't re-authorize the caller: a system:roles-only caller viewing a role
// shared to it (not owned by it) holds no system:ou/system:ou:view permission on the role's
// actual owning OU, so this lookup must run under a runtime context or the real internal/ou
// service would reject it as Unauthorized.
func (suite *RoleServiceTestSuite) TestGetRole_AllowsOutsideCallerOwnOU_Shared() {
	expectedRole := RoleWithPermissions{ID: "role1", Name: "Admin", OUID: "ou1"}
	suite.mockStore.On("GetRole", mock.Anything, "role1").Return(expectedRole, nil)
	suite.sharingService.isSharedFunc = func(
		context.Context, sharing.ResourceType, string, string,
	) (bool, *tidcommon.ServiceError) {
		return true, nil
	}
	suite.mockOUService.On("GetOrganizationUnit",
		mock.MatchedBy(security.IsRuntimeContext),
		"ou1").Return(providers.OrganizationUnit{ID: "ou1", Handle: "default"}, nil)

	result, err := suite.service.GetRoleWithPermissions(testOwnOUContext("sharee-ou"), "role1")

	suite.Nil(err)
	suite.NotNil(result)
}

func (suite *RoleServiceTestSuite) TestGetRole_OUHandleError() {
	expectedRole := RoleWithPermissions{
		ID:   "role1",
		Name: "Admin",
		OUID: "ou1",
	}

	suite.mockStore.On("GetRole", mock.Anything, "role1").Return(expectedRole, nil)
	suite.mockOUService.On("GetOrganizationUnit", mock.Anything,
		"ou1").Return(providers.OrganizationUnit{}, &tidcommon.ServiceError{Code: "INTERNAL_ERROR"})

	result, err := suite.service.GetRoleWithPermissions(testRootContext(), "role1")

	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal("role1", result.ID)
	suite.Equal("Admin", result.Name)
	suite.Equal("", result.OUHandle)
}

func (suite *RoleServiceTestSuite) TestGetRole_MissingID() {
	result, err := suite.service.GetRoleWithPermissions(testRootContext(), "")

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(ErrorMissingRoleID.Code, err.Code)
}

func (suite *RoleServiceTestSuite) TestGetRole_NotFound() {
	suite.mockStore.On("GetRole", mock.Anything,
		"nonexistent").Return(RoleWithPermissions{}, ErrRoleNotFound)

	result, err := suite.service.GetRoleWithPermissions(testRootContext(), "nonexistent")

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(ErrorRoleNotFound.Code, err.Code)
}

func (suite *RoleServiceTestSuite) TestGetRole_StoreError() {
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{}, errors.New("database error"))

	result, err := suite.service.GetRoleWithPermissions(testRootContext(), "role1")

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

// UpdateRole Tests
func (suite *RoleServiceTestSuite) TestUpdateRole_MissingRoleID() {
	request := RoleUpdateDetail{
		Name:        "New Name",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
	}

	result, err := suite.service.UpdateRoleWithPermissions(testRootContext(), "", request)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(ErrorMissingRoleID.Code, err.Code)
}

func (suite *RoleServiceTestSuite) TestUpdateRole_ValidationErrors() {
	testCases := []struct {
		name    string
		request RoleUpdateDetail
		errCode string
	}{
		{
			name: "MissingName",
			request: RoleUpdateDetail{
				OUID: "ou1",
				Permissions: []ResourcePermissions{{
					ResourceServerID: "rs1",
					Permissions:      []string{"perm1"},
				}},
			},
			errCode: ErrorInvalidRequestFormat.Code,
		},
		{
			name: "MissingOrgUnit",
			request: RoleUpdateDetail{
				Name: "Role",
				Permissions: []ResourcePermissions{{
					ResourceServerID: "rs1",
					Permissions:      []string{"perm1"},
				}},
			},
			errCode: ErrorInvalidRequestFormat.Code,
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			result, err := suite.service.UpdateRoleWithPermissions(testRootContext(), "role1", tc.request)
			suite.Nil(result)
			suite.NotNil(err)
			suite.Equal(tc.errCode, err.Code)
		})
	}
}

func (suite *RoleServiceTestSuite) TestUpdateRole_IsRoleExistError() {
	request := RoleUpdateDetail{
		Name:        "New Name",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
	}

	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"perm1"}).Return([]string{}, nil)
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{}, errors.New("database error"))

	result, err := suite.service.UpdateRoleWithPermissions(testRootContext(), "role1", request)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

func (suite *RoleServiceTestSuite) TestUpdateRole_OUNotFound() {
	request := RoleUpdateDetail{
		Name:        "New Name",
		OUID:        "nonexistent_ou",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
	}

	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"perm1"}).Return([]string{}, nil)
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "nonexistent_ou").
		Return(providers.OrganizationUnit{}, &oupkg.ErrorOrganizationUnitNotFound)

	result, err := suite.service.UpdateRoleWithPermissions(testRootContext(), "role1", request)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(ErrorOrganizationUnitNotFound.Code, err.Code)
}

func (suite *RoleServiceTestSuite) TestUpdateRole_OUServiceError() {
	request := RoleUpdateDetail{
		Name:        "New Name",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
	}

	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"perm1"}).Return([]string{}, nil)
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "ou1").
		Return(providers.OrganizationUnit{}, &tidcommon.ServiceError{Code: "INTERNAL_ERROR"})

	result, err := suite.service.UpdateRoleWithPermissions(testRootContext(), "role1", request)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

func (suite *RoleServiceTestSuite) TestUpdateRole_UpdateStoreError() {
	request := RoleUpdateDetail{
		Name:        "New Name",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
	}

	ou := providers.OrganizationUnit{ID: "ou1"}
	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"perm1"}).Return([]string{}, nil)
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "ou1").Return(ou, nil)
	suite.mockStore.On("CheckRoleNameExistsExcludingID", mock.Anything,
		"ou1", "New Name", "role1").Return(false, nil)
	suite.mockStore.On("UpdateRole", mock.Anything,
		mock.AnythingOfType("string"),
		mock.AnythingOfType("RoleUpdateDetail")).Return(errors.New("update error"))

	result, err := suite.service.UpdateRoleWithPermissions(testRootContext(), "role1", request)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

func (suite *RoleServiceTestSuite) TestUpdateRole_Success() {
	// This test also verifies permission validation is called correctly during update
	request := RoleUpdateDetail{
		Name:        "New Name",
		Description: "Updated description",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1", "perm2"}}},
	}

	ou := providers.OrganizationUnit{ID: "ou1", Handle: "default"}
	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"perm1", "perm2"}).Return([]string{}, nil)
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "ou1").Return(ou, nil)
	suite.mockStore.On("CheckRoleNameExistsExcludingID", mock.Anything,
		"ou1", "New Name", "role1").Return(false, nil)
	suite.mockStore.On("UpdateRole", mock.Anything,
		mock.AnythingOfType("string"),
		mock.AnythingOfType("RoleUpdateDetail")).Return(nil)

	result, err := suite.service.UpdateRoleWithPermissions(testRootContext(), "role1", request)

	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal("New Name", result.Name)
	suite.Equal("Updated description", result.Description)
	suite.Equal("default", result.OUHandle)
	// Verify permission validation was called
	suite.mockResourceService.AssertCalled(suite.T(), "ValidatePermissions", mock.Anything,
		"rs1", []string{"perm1", "perm2"})
}

// TestUpdateRole_WrapsOUServiceCallWithRuntimeContext proves the OU-existence lookup doesn't
// re-authorize a caller who already passed RequireOwnership above, mirroring
// TestCreateRole_WrapsOUServiceCallWithRuntimeContext for the update path.
func (suite *RoleServiceTestSuite) TestUpdateRole_WrapsOUServiceCallWithRuntimeContext() {
	request := RoleUpdateDetail{
		Name: "New Name",
		OUID: "ou1",
	}

	ou := providers.OrganizationUnit{ID: "ou1", Handle: "default"}
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockOUService.On("GetOrganizationUnit",
		mock.MatchedBy(security.IsRuntimeContext),
		"ou1").Return(ou, nil)
	suite.mockStore.On("CheckRoleNameExistsExcludingID", mock.Anything,
		"ou1", "New Name", "role1").Return(false, nil)
	suite.mockStore.On("UpdateRole", mock.Anything,
		mock.AnythingOfType("string"),
		mock.AnythingOfType("RoleUpdateDetail")).Return(nil)

	result, err := suite.service.UpdateRoleWithPermissions(testOwnOUContext("ou1"), "role1", request)

	suite.Nil(err)
	suite.NotNil(result)
}

// TestUpdateRole_RejectsWhenCallerDoesNotOwnExistingRole proves core config edits are gated by
// sharing.RequireOwnership against the role's existing owning OU before any mutation is attempted.
func (suite *RoleServiceTestSuite) TestUpdateRole_RejectsWhenCallerDoesNotOwnExistingRole() {
	request := RoleUpdateDetail{
		Name:        "New Name",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
	}

	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"perm1"}).Return([]string{}, nil)
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.sharingService.requireOwnershipFunc = func(
		_ context.Context, resourceType sharing.ResourceType, owningOUID string,
	) *tidcommon.ServiceError {
		suite.Equal(roleSharingResourceType, resourceType)
		suite.Equal("ou1", owningOUID)
		return &sharing.ErrorCoreConfigOwnerOnly
	}

	result, err := suite.service.UpdateRoleWithPermissions(testRootContext(), "role1", request)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(sharing.ErrorCoreConfigOwnerOnly.Code, err.Code)
	suite.mockOUService.AssertNotCalled(suite.T(), "GetOrganizationUnit", mock.Anything, mock.Anything)
}

// TestUpdateRole_RejectsWhenMovingToOUCallerDoesNotOwn proves that moving a role to a different OU
// requires ownership of *both* the existing and the destination OU: the first RequireOwnership
// call (existing OU) is allowed, but the second (destination OU) is denied.
func (suite *RoleServiceTestSuite) TestUpdateRole_RejectsWhenMovingToOUCallerDoesNotOwn() {
	request := RoleUpdateDetail{
		Name:        "New Name",
		OUID:        "ou2",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
	}

	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"perm1"}).Return([]string{}, nil)
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.sharingService.requireOwnershipFunc = func(
		_ context.Context, _ sharing.ResourceType, owningOUID string,
	) *tidcommon.ServiceError {
		if owningOUID == "ou1" {
			return nil
		}
		return &sharing.ErrorCoreConfigOwnerOnly
	}

	result, err := suite.service.UpdateRoleWithPermissions(testRootContext(), "role1", request)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(sharing.ErrorCoreConfigOwnerOnly.Code, err.Code)
	suite.mockOUService.AssertNotCalled(suite.T(), "GetOrganizationUnit", mock.Anything, mock.Anything)
}

func (suite *RoleServiceTestSuite) TestUpdateRole_RoleNotFound() {
	request := RoleUpdateDetail{
		Name:        "New Name",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
	}

	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"perm1"}).Return([]string{}, nil)
	suite.mockStore.On("GetRole", mock.Anything,
		"nonexistent").Return(RoleWithPermissions{}, ErrRoleNotFound)

	result, err := suite.service.UpdateRoleWithPermissions(testRootContext(), "nonexistent", request)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(ErrorRoleNotFound.Code, err.Code)
}

func (suite *RoleServiceTestSuite) TestUpdateRole_NameConflict() {
	request := RoleUpdateDetail{
		Name:        "Conflicting Name",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
	}

	ou := providers.OrganizationUnit{ID: "ou1"}
	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"perm1"}).Return([]string{}, nil)
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "ou1").Return(ou, nil)
	suite.mockStore.On("CheckRoleNameExistsExcludingID", mock.Anything,
		"ou1", "Conflicting Name",
		"role1").Return(true, nil)

	result, err := suite.service.UpdateRoleWithPermissions(testRootContext(), "role1", request)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(ErrorRoleNameConflict.Code, err.Code)
}

func (suite *RoleServiceTestSuite) TestUpdateRole_CheckNameExistsError() {
	request := RoleUpdateDetail{
		Name:        "New Name",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
	}

	ou := providers.OrganizationUnit{ID: "ou1"}
	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"perm1"}).Return([]string{}, nil)
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "ou1").Return(ou, nil)
	suite.mockStore.On("CheckRoleNameExistsExcludingID", mock.Anything,
		"ou1", "New Name", "role1").
		Return(false, errors.New("database error"))

	result, err := suite.service.UpdateRoleWithPermissions(testRootContext(), "role1", request)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

func (suite *RoleServiceTestSuite) TestUpdateRole_PermissionValidationErrors() {
	testCases := []struct {
		name          string
		request       RoleUpdateDetail
		setupMocks    func()
		expectedError *tidcommon.ServiceError
	}{
		{
			name: "InvalidPermissionsOnUpdate",
			request: RoleUpdateDetail{
				Name:        "Updated Role",
				OUID:        "ou1",
				Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
			},
			setupMocks: func() {
				// Permission validation happens before the IsRoleExist check in UpdateRole
				suite.mockResourceService.On("ValidatePermissions", mock.Anything,
					"rs1", []string{"perm1"}).
					Return([]string{"perm1"}, nil).Once()
			},
			expectedError: &ErrorInvalidPermissions,
		},
		{
			name: "PermissionValidationServiceError",
			request: RoleUpdateDetail{
				Name:        "Updated Role",
				OUID:        "ou1",
				Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
			},
			setupMocks: func() {
				// Permission validation happens before the IsRoleExist check in UpdateRole
				suite.mockResourceService.On("ValidatePermissions", mock.Anything,
					"rs1", []string{"perm1"}).
					Return([]string{}, &tidcommon.ServiceError{Code: "INTERNAL_ERROR"}).Once()
			},
			expectedError: &tidcommon.InternalServerError,
		},
		{
			name: "EmptyResourceServerIDOnUpdate",
			request: RoleUpdateDetail{
				Name:        "Updated Role",
				OUID:        "ou1",
				Permissions: []ResourcePermissions{{ResourceServerID: "", Permissions: []string{"perm1"}}},
			},
			setupMocks: func() {
				// Resource service should not be called for empty resource server ID
				// Early validation should fail before any other calls
			},
			expectedError: &ErrorInvalidPermissions,
		},
		{
			name: "MultipleResourceServersOnUpdate",
			request: RoleUpdateDetail{
				Name:        "Updated Role",
				Description: "Updated description",
				OUID:        "ou1",
				Permissions: []ResourcePermissions{
					{ResourceServerID: "rs1", Permissions: []string{"perm1"}},
					{ResourceServerID: "rs2", Permissions: []string{"perm2"}},
				},
			},
			setupMocks: func() {
				ou := providers.OrganizationUnit{ID: "ou1"}
				suite.mockStore.On("GetRole", mock.Anything,
					"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil).Once()
				suite.mockResourceService.On("ValidatePermissions", mock.Anything,
					"rs1", []string{"perm1"}).
					Return([]string{}, nil).Once()
				suite.mockResourceService.On("ValidatePermissions", mock.Anything,
					"rs2", []string{"perm2"}).
					Return([]string{}, nil).Once()
				suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "ou1").Return(ou, nil).Once()
				suite.mockStore.On("CheckRoleNameExistsExcludingID", mock.Anything,
					"ou1",
					"Updated Role", "role1").Return(false, nil).Once()
				suite.mockStore.On("UpdateRole", mock.Anything,
					mock.AnythingOfType("string"),
					mock.AnythingOfType("RoleUpdateDetail")).Return(nil).Once()
			},
			expectedError: nil, // Success case
		},
		{
			name: "EmptyPermissionsArrayOnUpdate",
			request: RoleUpdateDetail{
				Name:        "Updated Role",
				Description: "Updated description",
				OUID:        "ou1",
				Permissions: []ResourcePermissions{},
			},
			setupMocks: func() {
				ou := providers.OrganizationUnit{ID: "ou1"}
				suite.mockStore.On("GetRole", mock.Anything,
					"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil).Once()
				suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "ou1").Return(ou, nil).Once()
				suite.mockStore.On("CheckRoleNameExistsExcludingID", mock.Anything,
					"ou1",
					"Updated Role", "role1").Return(false, nil).Once()
				suite.mockStore.On("UpdateRole", mock.Anything,
					mock.AnythingOfType("string"),
					mock.AnythingOfType("RoleUpdateDetail")).Return(nil).Once()
				// Resource service should NOT be called for empty permissions
			},
			expectedError: nil, // Success case
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			// Setup fresh mocks for this test case
			suite.SetupTest()
			tc.setupMocks()

			result, err := suite.service.UpdateRoleWithPermissions(testRootContext(), "role1", tc.request)

			if tc.expectedError != nil {
				suite.Nil(result)
				suite.NotNil(err)
				suite.Equal(tc.expectedError.Code, err.Code)
			} else {
				suite.Nil(err)
				suite.NotNil(result)
			}
		})
	}
}

// DeleteRole Tests
func (suite *RoleServiceTestSuite) TestDeleteRole_Success() {
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockStore.On("DeleteAssignmentsByRoleID", mock.Anything,
		"role1").Return(nil)
	suite.mockStore.On("DeleteRole", mock.Anything,
		"role1").Return(nil)

	err := suite.service.DeleteRole(testRootContext(), "role1")

	suite.Nil(err)
}

func (suite *RoleServiceTestSuite) TestDeleteRole_WithAssignments() {
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockStore.On("DeleteAssignmentsByRoleID", mock.Anything,
		"role1").Return(nil)
	suite.mockStore.On("DeleteRole", mock.Anything,
		"role1").Return(nil)

	err := suite.service.DeleteRole(testRootContext(), "role1")

	suite.Nil(err)
}

// TestDeleteRole_RejectsWhenCallerDoesNotOwnRole proves deletion is gated by
// sharing.RequireOwnershipForDeletion (not RequireOwnership) before any assignment or role
// deletion is attempted, and that DeleteRole propagates whatever error that call returns —
// including a resource-type-specific one, not just the generic core-config error.
func (suite *RoleServiceTestSuite) TestDeleteRole_RejectsWhenCallerDoesNotOwnRole() {
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.sharingService.requireOwnershipForDeletionFunc = func(
		_ context.Context, resourceType sharing.ResourceType, owningOUID string,
	) *tidcommon.ServiceError {
		suite.Equal(roleSharingResourceType, resourceType)
		suite.Equal("ou1", owningOUID)
		return &ErrorRoleDeletionRestrictedToOwner
	}

	err := suite.service.DeleteRole(testRootContext(), "role1")

	suite.NotNil(err)
	suite.Equal(ErrorRoleDeletionRestrictedToOwner.Code, err.Code)
	suite.mockStore.AssertNotCalled(suite.T(), "DeleteAssignmentsByRoleID", mock.Anything, mock.Anything)
	suite.mockStore.AssertNotCalled(suite.T(), "DeleteRole", mock.Anything, mock.Anything)
}

func (suite *RoleServiceTestSuite) TestDeleteRole_NotFound_ReturnsNil() {
	suite.mockStore.On("GetRole", mock.Anything,
		"nonexistent").Return(RoleWithPermissions{}, ErrRoleNotFound)

	err := suite.service.DeleteRole(testRootContext(), "nonexistent")

	suite.Nil(err)
}

func (suite *RoleServiceTestSuite) TestDeleteRole_MissingID() {
	err := suite.service.DeleteRole(testRootContext(), "")

	suite.NotNil(err)
	suite.Equal(ErrorMissingRoleID.Code, err.Code)
}

func (suite *RoleServiceTestSuite) TestDeleteRole_IsRoleExistError() {
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{}, errors.New("database error"))

	err := suite.service.DeleteRole(testRootContext(), "role1")

	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

func (suite *RoleServiceTestSuite) TestDeleteRole_GetAssignmentsCountError() {
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockStore.On("DeleteAssignmentsByRoleID", mock.Anything,
		"role1").Return(errors.New("database error"))

	err := suite.service.DeleteRole(testRootContext(), "role1")

	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

func (suite *RoleServiceTestSuite) TestDeleteRole_StoreError() {
	suite.mockStore.On("GetRole", mock.Anything,
		"role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockStore.On("DeleteAssignmentsByRoleID", mock.Anything,
		"role1").Return(nil)
	suite.mockStore.On("DeleteRole", mock.Anything,
		"role1").Return(errors.New("delete error"))

	err := suite.service.DeleteRole(testRootContext(), "role1")

	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

// DeleteRole Declarative Mode Tests
func (suite *RoleServiceTestSuite) TestDeleteRole_DeclarativeMode_Denied() {
	// Setup declarative-only mode
	testConfig := &config.Config{
		DeclarativeResources: config.DeclarativeResources{
			Enabled: true,
		},
		Role: config.RoleConfig{
			Store: "declarative",
		},
	}
	config.ResetServerRuntime()
	initErr := config.InitializeServerRuntime("/tmp/test", testConfig)
	if initErr != nil {
		suite.Fail("Failed to initialize runtime", initErr)
	}
	defer config.ResetServerRuntime()

	suite.mockStore.On("GetRole", mock.Anything, "role1").Return(RoleWithPermissions{ID: "role1", OUID: "ou1"}, nil)
	suite.mockStore.On("IsRoleDeclarative", mock.Anything, "role1").Return(true, nil)

	err2 := suite.service.DeleteRole(testRootContext(), "role1")

	suite.NotNil(err2)
	suite.Equal(ErrorImmutableRole.Code, err2.Code)
}

// validateAssignmentIDs Tests
func (suite *RoleServiceTestSuite) TestValidateAssignmentIDs_UserServiceError() {
	request := RoleCreationDetail{
		Name:        "Test Role",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
		Assignments: []RoleAssignment{{ID: "user1", Type: AssigneeTypeUser}},
	}

	ou := providers.OrganizationUnit{ID: "ou1"}
	suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "ou1").Return(ou, nil)
	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"perm1"}).Return([]string{}, nil)
	suite.mockEntityService.On("GetEntitiesByIDs", mock.Anything,
		[]string{"user1"}).
		Return([]providers.Entity{}, errors.New("internal error"))

	result, err := suite.service.CreateRole(testRootContext(), request)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

func (suite *RoleServiceTestSuite) TestValidateAssignmentIDs_GroupServiceError() {
	request := RoleCreationDetail{
		Name:        "Test Role",
		OUID:        "ou1",
		Permissions: []ResourcePermissions{{ResourceServerID: "rs1", Permissions: []string{"perm1"}}},
		Assignments: []RoleAssignment{{ID: "group1", Type: AssigneeTypeGroup}},
	}

	ou := providers.OrganizationUnit{ID: "ou1"}
	suite.mockOUService.On("GetOrganizationUnit", mock.Anything, "ou1").Return(ou, nil)
	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"perm1"}).Return([]string{}, nil)
	suite.mockGroupService.On("ValidateGroupIDs", mock.Anything,
		[]string{"group1"}).
		Return(&tidcommon.ServiceError{Code: "INTERNAL_ERROR"})

	result, err := suite.service.CreateRole(testRootContext(), request)

	suite.Nil(result)
	suite.NotNil(err)
	suite.Equal(tidcommon.InternalServerError.Code, err.Code)
}

// Utility functions tests
func (suite *RoleServiceTestSuite) TestBuildPaginationLinks() {
	testCases := []struct {
		name        string
		base        string
		limit       int
		offset      int
		totalCount  int
		expectFirst bool
		expectPrev  bool
		expectNext  bool
		expectLast  bool
	}{
		{
			name:        "FirstPage",
			base:        "/roles",
			limit:       10,
			offset:      0,
			totalCount:  30,
			expectFirst: false,
			expectPrev:  false,
			expectNext:  true,
			expectLast:  true,
		},
		{
			name:        "MiddlePage",
			base:        "/roles",
			limit:       10,
			offset:      10,
			totalCount:  30,
			expectFirst: true,
			expectPrev:  true,
			expectNext:  true,
			expectLast:  true,
		},
		{
			name:        "LastPage",
			base:        "/roles",
			limit:       10,
			offset:      20,
			totalCount:  30,
			expectFirst: true,
			expectPrev:  true,
			expectNext:  false,
			expectLast:  false,
		},
		{
			name:        "SinglePage",
			base:        "/roles",
			limit:       10,
			offset:      0,
			totalCount:  5,
			expectFirst: false,
			expectPrev:  false,
			expectNext:  false,
			expectLast:  false,
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			links := utils.BuildPaginationLinks(tc.base, tc.limit, tc.offset, tc.totalCount, "")

			hasFirst := false
			hasPrev := false
			hasNext := false
			hasLast := false

			for _, link := range links {
				switch link.Rel {
				case "first":
					hasFirst = true
				case "prev":
					hasPrev = true
				case "next":
					hasNext = true
				case "last":
					hasLast = true
				}
			}

			suite.Equal(tc.expectFirst, hasFirst, "first link mismatch")
			suite.Equal(tc.expectPrev, hasPrev, "prev link mismatch")
			suite.Equal(tc.expectNext, hasNext, "next link mismatch")
			suite.Equal(tc.expectLast, hasLast, "last link mismatch")
		})
	}
}

// GetAuthorizedPermissions Tests - Consolidated for efficiency while maintaining coverage
func (suite *RoleServiceTestSuite) TestGetAuthorizedPermissions() {
	testCases := []struct {
		name                 string
		userID               string
		groups               []string
		requestedPermissions []string
		mockReturn           []string
		mockError            error
		expectedPermissions  []string
		expectedError        *tidcommon.ServiceError
		skipMock             bool
	}{
		{
			name:                 "Success_UserAndGroups",
			userID:               testUserID1,
			groups:               []string{"group1", "group2"},
			requestedPermissions: []string{"perm1", "perm2", "perm3"},
			mockReturn:           []string{"perm1", "perm3"},
			expectedPermissions:  []string{"perm1", "perm3"},
		},
		{
			name:                 "Success_UserOnly_NilGroupsNormalized",
			userID:               testUserID1,
			groups:               nil, // Tests both nil and empty groups normalization
			requestedPermissions: []string{"perm1", "perm2"},
			mockReturn:           []string{"perm1"},
			expectedPermissions:  []string{"perm1"},
		},
		{
			name:                 "Success_GroupsOnly",
			userID:               "",
			groups:               []string{"group1", "group2"},
			requestedPermissions: []string{"perm1", "perm2"},
			mockReturn:           []string{"perm1"},
			expectedPermissions:  []string{"perm1"},
		},
		{
			name:                 "Success_NoAuthorizedPermissions",
			userID:               testUserID1,
			groups:               []string{"group1"},
			requestedPermissions: []string{"perm1", "perm2"},
			mockReturn:           []string{}, // User has no permissions
			expectedPermissions:  []string{},
		},
		{
			name:                 "Success_AllPermissionsAuthorized",
			userID:               testUserID1,
			groups:               []string{"group1"},
			requestedPermissions: []string{"perm1", "perm2"},
			mockReturn:           []string{"perm1", "perm2"}, // All permissions authorized
			expectedPermissions:  []string{"perm1", "perm2"},
		},
		{
			name:                 "EmptyAndNilRequestedPermissions_ReturnsEmpty",
			userID:               testUserID1,
			groups:               []string{"group1"},
			requestedPermissions: nil, // Also covers empty []string{} case
			expectedPermissions:  []string{},
			skipMock:             true, // No store call for empty permissions
		},
		{
			name:                 "MissingUserAndGroups_Error",
			userID:               "",
			groups:               nil, // Covers both nil and empty cases
			requestedPermissions: []string{"perm1", "perm2"},
			expectedError:        &ErrorMissingEntityOrGroups,
			skipMock:             true,
		},
		{
			name:                 "StoreError_ReturnsInternalError",
			userID:               testUserID1,
			groups:               []string{"group1"},
			requestedPermissions: []string{"perm1", "perm2"},
			mockError:            errors.New("database error"),
			expectedError:        &tidcommon.InternalServerError,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			if !tc.skipMock {
				normalizedGroups := tc.groups
				if normalizedGroups == nil {
					normalizedGroups = []string{}
				}
				suite.mockStore.On("GetAuthorizedPermissionsByResourceServer", mock.Anything,
					tc.userID, normalizedGroups, "",
					tc.requestedPermissions, "").
					Return(tc.mockReturn, tc.mockError).Once()
			}

			result, err := suite.service.GetAuthorizedPermissionsByResourceServer(
				testRootContext(), tc.userID, tc.groups, "",
				tc.requestedPermissions, "")

			if tc.expectedError != nil {
				suite.NotNil(err)
				suite.Equal(tc.expectedError.Code, err.Code)
				suite.Nil(result)
			} else {
				suite.Nil(err)
				suite.NotNil(result)
				if len(tc.requestedPermissions) == 0 {
					suite.Equal(0, len(result))
				} else {
					suite.Equal(len(tc.expectedPermissions), len(result))
					suite.Equal(tc.expectedPermissions, result)
				}
			}
		})
	}
}

// Tests for IsRoleDeclarative (public method)
func (suite *RoleServiceTestSuite) TestIsRoleDeclarative_ReturnsTrue() {
	suite.mockStore.On("IsRoleDeclarative", mock.Anything, "declarative-role").Return(true, nil)

	isDeclarative, err := suite.service.IsRoleDeclarative(testRootContext(), "declarative-role")

	suite.Nil(err)
	suite.True(isDeclarative)
	suite.mockStore.AssertCalled(suite.T(), "IsRoleDeclarative", mock.Anything, "declarative-role")
}

func (suite *RoleServiceTestSuite) TestIsRoleDeclarative_ReturnsFalse() {
	suite.mockStore.On("IsRoleDeclarative", mock.Anything, "mutable-role").Return(false, nil)

	isDeclarative, err := suite.service.IsRoleDeclarative(testRootContext(), "mutable-role")

	suite.Nil(err)
	suite.False(isDeclarative)
}

func (suite *RoleServiceTestSuite) TestIsRoleDeclarative_StoreReturnsError() {
	storeErr := errors.New("store error")
	suite.mockStore.On("IsRoleDeclarative", mock.Anything, "role-id").Return(false, storeErr)

	isDeclarative, err := suite.service.IsRoleDeclarative(testRootContext(), "role-id")

	suite.NotNil(err)
	suite.False(isDeclarative)
	suite.Equal(&tidcommon.InternalServerError, err)
}

// TestResolveRoleOUHandle_OUHandleResolved verifies that when only ou_handle is set, it is
// resolved to ou_id via the OU service.
func (suite *RoleServiceTestSuite) TestResolveRoleOUHandle_OUHandleResolved() {
	suite.mockOUService.On("GetOrganizationUnitByPath", mock.Anything, "default").
		Return(providers.OrganizationUnit{ID: "ou-resolved"}, (*tidcommon.ServiceError)(nil)).Once()

	role := &RoleWithPermissionsAndAssignments{OUHandle: "default"}
	svcErr := suite.service.ResolveRoleOUHandle(testRootContext(), role)

	suite.Nil(svcErr)
	suite.Equal("ou-resolved", role.OUID)
}

// TestResolveRoleOUHandle_OUIDAlreadySet verifies that no resolution happens when ou_id is set
// and ou_handle is empty.
func (suite *RoleServiceTestSuite) TestResolveRoleOUHandle_OUIDAlreadySet() {
	role := &RoleWithPermissionsAndAssignments{OUID: "ou-direct"}
	svcErr := suite.service.ResolveRoleOUHandle(testRootContext(), role)

	suite.Nil(svcErr)
	suite.Equal("ou-direct", role.OUID)
}

// TestResolveRoleOUHandle_BothProvided verifies that when both ou_id and ou_handle are
// provided, ou_id is retained and the OU service is never called.
func (suite *RoleServiceTestSuite) TestResolveRoleOUHandle_BothProvided() {
	role := &RoleWithPermissionsAndAssignments{ID: "r1", Name: "Admin", OUID: "ou-direct", OUHandle: "default"}

	svcErr := suite.service.ResolveRoleOUHandle(testRootContext(), role)

	suite.Nil(svcErr)
	suite.Equal("ou-direct", role.OUID)
	// AssertExpectations in t.Cleanup will confirm GetOrganizationUnitByPath was never invoked.
}

// TestResolveRoleOUHandle_OUHandleNotFound verifies that a not-found response from the OU
// service is surfaced as ErrorInvalidRequestFormat.
func (suite *RoleServiceTestSuite) TestResolveRoleOUHandle_OUHandleNotFound() {
	suite.mockOUService.On("GetOrganizationUnitByPath", mock.Anything, "missing").
		Return(providers.OrganizationUnit{}, &oupkg.ErrorOrganizationUnitNotFound).Once()

	role := &RoleWithPermissionsAndAssignments{OUHandle: "missing"}
	svcErr := suite.service.ResolveRoleOUHandle(testRootContext(), role)

	suite.NotNil(svcErr)
	suite.Equal(ErrorInvalidRequestFormat.Code, svcErr.Code)
}

// TestResolveRoleOUHandle_NeitherProvided verifies that the call is a no-op when neither
// ou_id nor ou_handle is provided.
func (suite *RoleServiceTestSuite) TestResolveRoleOUHandle_NeitherProvided() {
	role := &RoleWithPermissionsAndAssignments{}
	svcErr := suite.service.ResolveRoleOUHandle(testRootContext(), role)

	suite.Nil(svcErr)
	suite.Empty(role.OUID)
}

// TestResolveRoleOUHandle_NilOUService verifies that a clear error is returned when the OU
// service is nil and ou_handle is supplied (no nil-pointer panic).
func (suite *RoleServiceTestSuite) TestResolveRoleOUHandle_NilOUService() {
	svc := &roleService{ouService: nil}
	role := &RoleWithPermissionsAndAssignments{OUHandle: "default"}

	svcErr := svc.ResolveRoleOUHandle(testRootContext(), role)

	suite.NotNil(svcErr)
	suite.Equal(tidcommon.InternalServerError.Code, svcErr.Code)
}

// TestRoleDeclarativeYAML_OUHandleParsed verifies that ou_handle is parsed off the YAML
// document into the role declarative resource.
func TestRoleDeclarativeYAML_OUHandleParsed(t *testing.T) {
	yamlData := []byte(`
id: role-1
name: Admin
ouHandle: default
permissions:
  - resourceServerId: rs1
    permissions:
      - read
`)
	role, err := parseToRole(yamlData)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.OUHandle != "default" {
		t.Errorf("OUHandle = %q, want %q", role.OUHandle, "default")
	}
	if role.OUID != "" {
		t.Errorf("OUID = %q, want empty (resolution happens later)", role.OUID)
	}
}

// CascadeDeleteDependencies Tests

func (suite *RoleServiceTestSuite) TestGetResourceDependencies_ReportsNoUsages() {
	deps, err := suite.service.GetResourceDependencies(
		context.Background(), resourcedependency.ResourceTypeResource, "res1")

	suite.NoError(err)
	suite.Empty(deps)
}

func (suite *RoleServiceTestSuite) TestCascadeDeleteDependencies_IgnoresUnrelatedResourceTypes() {
	for _, resourceType := range []string{
		resourcedependency.ResourceTypeUser,
		resourcedependency.ResourceTypeGroup,
		resourcedependency.ResourceTypeApplication,
	} {
		deleted, err := suite.service.CascadeDeleteDependencies(context.Background(), resourceType, "id1")

		suite.NoError(err)
		suite.Equal(0, deleted)
	}

	suite.mockStore.AssertNotCalled(suite.T(), "GetReferencedPermissions", mock.Anything)
}

func (suite *RoleServiceTestSuite) TestCascadeDeleteDependencies_RemovesOrphanedPermissions() {
	suite.mockStore.On("GetReferencedPermissions", mock.Anything).Return([]ResourcePermissions{
		{ResourceServerID: "rs1", Permissions: []string{"read", "write"}},
	}, nil)
	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"read", "write"}).Return([]string{"write"}, nil)
	suite.mockStore.On("DeleteRolePermission", mock.Anything, "rs1", "write").Return(int64(2), nil)

	deleted, err := suite.service.CascadeDeleteDependencies(
		context.Background(), resourcedependency.ResourceTypeAction, "action1")

	suite.NoError(err)
	suite.Equal(2, deleted)
	suite.mockStore.AssertNotCalled(suite.T(), "DeleteRolePermission", mock.Anything, "rs1", "read")
}

func (suite *RoleServiceTestSuite) TestCascadeDeleteDependencies_KeepsValidPermissions() {
	suite.mockStore.On("GetReferencedPermissions", mock.Anything).Return([]ResourcePermissions{
		{ResourceServerID: "rs1", Permissions: []string{"read"}},
	}, nil)
	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"read"}).Return([]string{}, nil)

	deleted, err := suite.service.CascadeDeleteDependencies(
		context.Background(), resourcedependency.ResourceTypeResource, "res1")

	suite.NoError(err)
	suite.Equal(0, deleted)
	suite.mockStore.AssertNotCalled(suite.T(), "DeleteRolePermission",
		mock.Anything, mock.Anything, mock.Anything)
}

// A deleted resource server invalidates every permission scoped to it, so all of them are removed
// while permissions of other resource servers are left alone.
func (suite *RoleServiceTestSuite) TestCascadeDeleteDependencies_RemovesAllPermissionsOfDeletedServer() {
	suite.mockStore.On("GetReferencedPermissions", mock.Anything).Return([]ResourcePermissions{
		{ResourceServerID: "rs1", Permissions: []string{"read", "write"}},
		{ResourceServerID: "rs2", Permissions: []string{"list"}},
	}, nil)
	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"read", "write"}).Return([]string{"read", "write"}, nil)
	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs2", []string{"list"}).Return([]string{}, nil)
	suite.mockStore.On("DeleteRolePermission", mock.Anything, "rs1", "read").Return(int64(1), nil)
	suite.mockStore.On("DeleteRolePermission", mock.Anything, "rs1", "write").Return(int64(1), nil)

	deleted, err := suite.service.CascadeDeleteDependencies(
		context.Background(), resourcedependency.ResourceTypeResourceServer, "rs1")

	suite.NoError(err)
	suite.Equal(2, deleted)
	suite.mockStore.AssertNotCalled(suite.T(), "DeleteRolePermission", mock.Anything, "rs2", "list")
}

func (suite *RoleServiceTestSuite) TestCascadeDeleteDependencies_StoreReadError() {
	suite.mockStore.On("GetReferencedPermissions", mock.Anything).
		Return([]ResourcePermissions{}, errors.New("database error"))

	deleted, err := suite.service.CascadeDeleteDependencies(
		context.Background(), resourcedependency.ResourceTypeResource, "res1")

	suite.Error(err)
	suite.Equal(0, deleted)
}

func (suite *RoleServiceTestSuite) TestCascadeDeleteDependencies_ValidationError() {
	suite.mockStore.On("GetReferencedPermissions", mock.Anything).Return([]ResourcePermissions{
		{ResourceServerID: "rs1", Permissions: []string{"read"}},
	}, nil)
	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"read"}).Return([]string(nil), &tidcommon.InternalServerError)

	deleted, err := suite.service.CascadeDeleteDependencies(
		context.Background(), resourcedependency.ResourceTypeResource, "res1")

	suite.Error(err)
	suite.Equal(0, deleted)
}

func (suite *RoleServiceTestSuite) TestCascadeDeleteDependencies_DeleteError() {
	suite.mockStore.On("GetReferencedPermissions", mock.Anything).Return([]ResourcePermissions{
		{ResourceServerID: "rs1", Permissions: []string{"read"}},
	}, nil)
	suite.mockResourceService.On("ValidatePermissions", mock.Anything,
		"rs1", []string{"read"}).Return([]string{"read"}, nil)
	suite.mockStore.On("DeleteRolePermission", mock.Anything, "rs1", "read").
		Return(int64(0), errors.New("database error"))

	deleted, err := suite.service.CascadeDeleteDependencies(
		context.Background(), resourcedependency.ResourceTypeResource, "res1")

	suite.Error(err)
	suite.Equal(0, deleted)
}

// newAllowAllRoleAuthz returns an authz mock that permits every grant check, so that
// tests unrelated to the guard need not configure it.
func newAllowAllRoleAuthz(t *testing.T) sysauthz.SystemAuthorizationServiceInterface {
	mockAuthz := sysauthzmock.NewSystemAuthorizationServiceInterfaceMock(t)
	mockAuthz.On("CanGrantPermissions", mock.Anything, mock.Anything).
		Return((*tidcommon.ServiceError)(nil)).Maybe()
	mockAuthz.On("CanGrantMembership", mock.Anything, mock.Anything, mock.Anything).
		Return((*tidcommon.ServiceError)(nil)).Maybe()
	return mockAuthz
}
