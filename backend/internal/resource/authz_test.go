// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"

	"github.com/thunder-id/thunderid/internal/sharing"
	"github.com/thunder-id/thunderid/internal/system/config"
	"github.com/thunder-id/thunderid/internal/system/security"
	"github.com/thunder-id/thunderid/tests/mocks/oumock"
)

// ResourceAuthzTestSuite covers the system:resource-servers / system:resource-servers:view OU
// confinement added in authz.go: a caller holding either scope (but not the root permission) may
// only act within its own token-issued organization unit, or on a resource shared to it. Mirrors
// internal/role's own requireOwnOUScope tests.
type ResourceAuthzTestSuite struct {
	suite.Suite
	mockStore      *resourceStoreInterfaceMock
	mockOU         *oumock.OrganizationUnitServiceInterfaceMock
	sharingService *fakeSharingService
	service        *resourceService
}

func TestResourceAuthzTestSuite(t *testing.T) {
	suite.Run(t, new(ResourceAuthzTestSuite))
}

func (suite *ResourceAuthzTestSuite) SetupTest() {
	config.ResetServerRuntime()
	require.NoError(suite.T(), config.InitializeServerRuntime("/tmp/test", &config.Config{}))

	suite.mockStore = newResourceStoreInterfaceMock(suite.T())
	suite.mockOU = new(oumock.OrganizationUnitServiceInterfaceMock)
	suite.sharingService = &fakeSharingService{}
	svc, err := newResourceService(suite.mockOU, suite.mockStore, &fakeTransactioner{}, suite.sharingService)
	require.NoError(suite.T(), err)
	suite.service = svc.(*resourceService)
}

func (suite *ResourceAuthzTestSuite) TearDownTest() {
	config.ResetServerRuntime()
}

// --- requireOwnOUScope ---

func (suite *ResourceAuthzTestSuite) TestRequireOwnOUScope() {
	testCases := []struct {
		name        string
		ctx         context.Context
		targetOUID  string
		expectError bool
	}{
		{
			name:        "RootPermissionBypassesEntirely",
			ctx:         testRootContext(),
			targetOUID:  "some-other-ou",
			expectError: false,
		},
		{
			name:        "RuntimeContextBypassesEntirely",
			ctx:         security.WithRuntimeContext(context.Background()),
			targetOUID:  "some-other-ou",
			expectError: false,
		},
		{
			name:        "OwnOUAllowed",
			ctx:         testOwnOUContext("ou-1"),
			targetOUID:  "ou-1",
			expectError: false,
		},
		{
			name:        "ForeignOURejected",
			ctx:         testOwnOUContext("ou-1"),
			targetOUID:  "ou-2",
			expectError: true,
		},
		{
			// A caller whose token carries no ouId claim at all can reach nothing OU-scoped:
			// "" never equals a real target OU, so this fails closed.
			name:        "NoOUClaimRejected",
			ctx:         testOwnOUContext(""),
			targetOUID:  "ou-1",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			svcErr := requireOwnOUScope(tc.ctx, tc.targetOUID)
			if tc.expectError {
				suite.Require().NotNil(svcErr)
				suite.Equal(ErrorResourceOutsideOwnOUScope.Code, svcErr.Code)
				return
			}
			suite.Nil(svcErr)
		})
	}
}

// --- RequireVisibility ---

func (suite *ResourceAuthzTestSuite) TestRequireVisibility_OwnOUSkipsSharingLookup() {
	// isSharedFunc deliberately left nil: any call panics via fakeSharingService, proving the
	// owner short-circuit returns before consulting the sharing framework.
	svcErr := suite.service.RequireVisibility(
		testOwnOUContext("ou-1"), resourceServerSharingType, "rs1", "ou-1")
	suite.Nil(svcErr)
}

func (suite *ResourceAuthzTestSuite) TestRequireVisibility_RootSkipsSharingLookup() {
	svcErr := suite.service.RequireVisibility(
		testRootContext(), resourceServerSharingType, "rs1", "owner-ou")
	suite.Nil(svcErr)
}

func (suite *ResourceAuthzTestSuite) TestRequireVisibility_ForeignOUAllowedWhenShared() {
	suite.sharingService.isSharedFunc = func(
		_ context.Context, resourceType sharing.ResourceType, resourceID, ouID string,
	) (bool, *tidcommon.ServiceError) {
		suite.Equal(resourceServerSharingType, resourceType)
		suite.Equal("rs1", resourceID)
		suite.Equal("sharee-ou", ouID)
		return true, nil
	}

	svcErr := suite.service.RequireVisibility(
		testOwnOUContext("sharee-ou"), resourceServerSharingType, "rs1", "owner-ou")
	suite.Nil(svcErr)
}

func (suite *ResourceAuthzTestSuite) TestRequireVisibility_ForeignOURejectedWhenNotShared() {
	suite.sharingService.isSharedFunc = func(
		_ context.Context, _ sharing.ResourceType, _, _ string,
	) (bool, *tidcommon.ServiceError) {
		return false, nil
	}

	svcErr := suite.service.RequireVisibility(
		testOwnOUContext("stranger-ou"), resourceServerSharingType, "rs1", "owner-ou")
	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorResourceOutsideOwnOUScope.Code, svcErr.Code)
}

func (suite *ResourceAuthzTestSuite) TestRequireVisibility_SharingLookupErrorPropagates() {
	expected := &tidcommon.ServiceError{Code: "SHR-9999"}
	suite.sharingService.isSharedFunc = func(
		_ context.Context, _ sharing.ResourceType, _, _ string,
	) (bool, *tidcommon.ServiceError) {
		return false, expected
	}

	svcErr := suite.service.RequireVisibility(
		testOwnOUContext("stranger-ou"), resourceServerSharingType, "rs1", "owner-ou")
	suite.Equal(expected, svcErr)
}

// --- Create paths reject a foreign OU (requireOwnOUScope wiring) ---

func (suite *ResourceAuthzTestSuite) TestCreateResourceServer_RejectsForeignOU() {
	// No OU-service or store expectations set: the scope check must run before any of them, so a
	// rejected caller cannot use this endpoint to probe which OU IDs exist.
	result, svcErr := suite.service.CreateResourceServer(testOwnOUContext("ou-1"), providers.ResourceServer{
		Name:       "rs",
		Identifier: "https://example.com/rs",
		OUID:       "ou-2",
	})
	suite.Nil(result)
	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorResourceOutsideOwnOUScope.Code, svcErr.Code)
}

func (suite *ResourceAuthzTestSuite) TestCreateResource_RejectsForeignOU() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou", Delimiter: ":"}, nil)

	result, svcErr := suite.service.CreateResource(
		testOwnOUContext("stranger-ou"), "rs1", providers.Resource{Name: "Books", Handle: "books"})
	suite.Nil(result)
	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorResourceOutsideOwnOUScope.Code, svcErr.Code)
}

func (suite *ResourceAuthzTestSuite) TestCreateAction_RejectsForeignOU() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou", Delimiter: ":"}, nil)

	result, svcErr := suite.service.CreateAction(
		testOwnOUContext("stranger-ou"), "rs1", nil, providers.Action{Name: "View", Handle: "view"})
	suite.Nil(result)
	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorResourceOutsideOwnOUScope.Code, svcErr.Code)
}

// A sharee OU must not be able to create resources/actions under a resource server merely shared
// to it: creating core config is owner-only, unlike reading it.
func (suite *ResourceAuthzTestSuite) TestCreateResource_RejectsShareeOU() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou", Delimiter: ":"}, nil)
	// isSharedFunc left nil: requireOwnOUScope must reject outright without consulting sharing,
	// since a grant never confers the right to add new core config.
	result, svcErr := suite.service.CreateResource(
		testOwnOUContext("sharee-ou"), "rs1", providers.Resource{Name: "Books", Handle: "books"})
	suite.Nil(result)
	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorResourceOutsideOwnOUScope.Code, svcErr.Code)
}

// --- Read paths honor share visibility (RequireVisibility wiring) ---

func (suite *ResourceAuthzTestSuite) TestGetResource_RejectsForeignOUWhenNotShared() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou"}, nil)
	suite.mockStore.On("GetResource", mock.Anything, "res1", "rs1").
		Return(providers.Resource{ID: "res1", Handle: "books"}, nil)
	suite.sharingService.isSharedFunc = func(
		_ context.Context, _ sharing.ResourceType, _, _ string,
	) (bool, *tidcommon.ServiceError) {
		return false, nil
	}

	result, svcErr := suite.service.GetResource(testOwnOUContext("stranger-ou"), "rs1", "res1")
	suite.Nil(result)
	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorResourceOutsideOwnOUScope.Code, svcErr.Code)
}

func (suite *ResourceAuthzTestSuite) TestGetResource_AllowsShareeOU() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou"}, nil)
	suite.mockStore.On("GetResource", mock.Anything, "res1", "rs1").
		Return(providers.Resource{ID: "res1", Handle: "books"}, nil)
	suite.sharingService.isSharedFunc = func(
		_ context.Context, resourceType sharing.ResourceType, resourceID, ouID string,
	) (bool, *tidcommon.ServiceError) {
		suite.Equal(resourceNodeSharingType, resourceType)
		suite.Equal("res1", resourceID)
		suite.Equal("sharee-ou", ouID)
		return true, nil
	}

	result, svcErr := suite.service.GetResource(testOwnOUContext("sharee-ou"), "rs1", "res1")
	suite.Nil(svcErr)
	suite.Require().NotNil(result)
	suite.Equal("res1", result.ID)
}

func (suite *ResourceAuthzTestSuite) TestGetAction_RejectsForeignOUWhenNotShared() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou"}, nil)
	suite.mockStore.On("GetAction", mock.Anything, "act1", "rs1", (*string)(nil)).
		Return(providers.Action{ID: "act1", Handle: "view"}, nil)
	suite.sharingService.isSharedFunc = func(
		_ context.Context, _ sharing.ResourceType, _, _ string,
	) (bool, *tidcommon.ServiceError) {
		return false, nil
	}

	result, svcErr := suite.service.GetAction(testOwnOUContext("stranger-ou"), "rs1", nil, "act1")
	suite.Nil(result)
	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorResourceOutsideOwnOUScope.Code, svcErr.Code)
}

// --- Update/Delete paths defer to sharing.RequireOwnership(ForDeletion) ---

func (suite *ResourceAuthzTestSuite) TestUpdateResourceServer_DefersToRequireOwnership() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou", Delimiter: ":"}, nil)
	suite.mockStore.On("IsResourceServerDeclarative", "rs1").Return(false)

	var seenOUIDs []string
	suite.sharingService.requireOwnershipFunc = func(
		_ context.Context, resourceType sharing.ResourceType, owningOUID string,
	) *tidcommon.ServiceError {
		suite.Equal(resourceServerSharingType, resourceType)
		seenOUIDs = append(seenOUIDs, owningOUID)
		return &sharing.ErrorCoreConfigOwnerOnly
	}

	result, svcErr := suite.service.UpdateResourceServer(
		testOwnOUContext("stranger-ou"), "rs1", providers.ResourceServer{Name: "rs", OUID: "owner-ou"})
	suite.Nil(result)
	suite.Require().NotNil(svcErr)
	suite.Equal(sharing.ErrorCoreConfigOwnerOnly.Code, svcErr.Code)
	suite.Equal([]string{"owner-ou"}, seenOUIDs, "checked against the existing record's own OU")
}

// Moving a resource server to a different OU must additionally prove ownership of the destination.
func (suite *ResourceAuthzTestSuite) TestUpdateResourceServer_OUMoveChecksBothOUs() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "ou-1", Delimiter: ":"}, nil)
	suite.mockStore.On("IsResourceServerDeclarative", "rs1").Return(false)

	var seenOUIDs []string
	suite.sharingService.requireOwnershipFunc = func(
		_ context.Context, _ sharing.ResourceType, owningOUID string,
	) *tidcommon.ServiceError {
		seenOUIDs = append(seenOUIDs, owningOUID)
		if owningOUID == "ou-2" {
			return &sharing.ErrorCoreConfigOwnerOnly
		}
		return nil
	}

	result, svcErr := suite.service.UpdateResourceServer(
		testOwnOUContext("ou-1"), "rs1", providers.ResourceServer{Name: "rs", OUID: "ou-2"})
	suite.Nil(result)
	suite.Require().NotNil(svcErr)
	suite.Equal([]string{"ou-1", "ou-2"}, seenOUIDs,
		"both the existing OU and the destination OU must be checked")
}

func (suite *ResourceAuthzTestSuite) TestDeleteResourceServer_DefersToRequireOwnershipForDeletion() {
	suite.mockStore.On("IsResourceServerDeclarative", "rs1").Return(false)
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou"}, nil)

	suite.sharingService.requireOwnershipForDeletionFunc = func(
		_ context.Context, resourceType sharing.ResourceType, owningOUID string,
	) *tidcommon.ServiceError {
		suite.Equal(resourceServerSharingType, resourceType)
		suite.Equal("owner-ou", owningOUID)
		return &sharing.ErrorCoreConfigOwnerOnly
	}

	svcErr := suite.service.DeleteResourceServer(testOwnOUContext("stranger-ou"), "rs1")
	suite.Require().NotNil(svcErr)
	suite.Equal(sharing.ErrorCoreConfigOwnerOnly.Code, svcErr.Code)
}

func (suite *ResourceAuthzTestSuite) TestUpdateResource_DefersToRequireOwnership() {
	suite.mockStore.On("IsResourceServerDeclarative", "rs1").Return(false)
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou"}, nil)
	suite.sharingService.requireOwnershipFunc = func(
		_ context.Context, resourceType sharing.ResourceType, owningOUID string,
	) *tidcommon.ServiceError {
		suite.Equal(resourceNodeSharingType, resourceType)
		suite.Equal("owner-ou", owningOUID)
		return &sharing.ErrorCoreConfigOwnerOnly
	}

	result, svcErr := suite.service.UpdateResource(
		testOwnOUContext("sharee-ou"), "rs1", "res1", providers.Resource{Name: "Books"})
	suite.Nil(result)
	suite.Require().NotNil(svcErr)
	suite.Equal(sharing.ErrorCoreConfigOwnerOnly.Code, svcErr.Code)
}

func (suite *ResourceAuthzTestSuite) TestDeleteAction_DefersToRequireOwnershipForDeletion() {
	suite.mockStore.On("IsResourceServerDeclarative", "rs1").Return(false)
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou"}, nil)
	suite.sharingService.requireOwnershipForDeletionFunc = func(
		_ context.Context, resourceType sharing.ResourceType, owningOUID string,
	) *tidcommon.ServiceError {
		suite.Equal(actionSharingType, resourceType)
		suite.Equal("owner-ou", owningOUID)
		return &sharing.ErrorCoreConfigOwnerOnly
	}

	svcErr := suite.service.DeleteAction(testOwnOUContext("sharee-ou"), "rs1", nil, "act1")
	suite.Require().NotNil(svcErr)
	suite.Equal(sharing.ErrorCoreConfigOwnerOnly.Code, svcErr.Code)
}

// --- Share-grant operations require visibility ---

func (suite *ResourceAuthzTestSuite) TestShareResourceServer_RejectsForeignOU() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou"}, nil)
	suite.sharingService.isSharedFunc = func(
		_ context.Context, _ sharing.ResourceType, _, _ string,
	) (bool, *tidcommon.ServiceError) {
		return false, nil
	}

	result, svcErr := suite.service.ShareResourceServer(
		testOwnOUContext("stranger-ou"), "rs1", ShareRequest{AllChildren: true})
	suite.Nil(result)
	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorResourceOutsideOwnOUScope.Code, svcErr.Code)
}

func (suite *ResourceAuthzTestSuite) TestListResourceServerGrants_RejectsForeignOU() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou"}, nil)
	suite.sharingService.isSharedFunc = func(
		_ context.Context, _ sharing.ResourceType, _, _ string,
	) (bool, *tidcommon.ServiceError) {
		return false, nil
	}

	result, svcErr := suite.service.ListResourceServerGrants(testOwnOUContext("stranger-ou"), "rs1")
	suite.Nil(result)
	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorResourceOutsideOwnOUScope.Code, svcErr.Code)
}

func (suite *ResourceAuthzTestSuite) TestUnshareResourceServerGrant_RejectsForeignOU() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou"}, nil)
	suite.sharingService.isSharedFunc = func(
		_ context.Context, _ sharing.ResourceType, _, _ string,
	) (bool, *tidcommon.ServiceError) {
		return false, nil
	}

	svcErr := suite.service.UnshareResourceServerGrant(testOwnOUContext("stranger-ou"), "rs1", "grant-1")
	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorResourceOutsideOwnOUScope.Code, svcErr.Code)
}

// A sharee OU may reshare what was shared to it (the sharing framework's own one-hop delegation
// rule then governs how far), so visibility, not ownership, is the right gate here.
func (suite *ResourceAuthzTestSuite) TestShareResourceServer_AllowsShareeOU() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou"}, nil)
	suite.mockStore.On("GetResourceListCount", mock.Anything, "rs1").Return(0, nil)
	suite.mockStore.On("GetActionListCount", mock.Anything, "rs1", (*string)(nil), providers.ActionKind("")).
		Return(0, nil)
	suite.sharingService.isSharedFunc = func(
		_ context.Context, _ sharing.ResourceType, _, _ string,
	) (bool, *tidcommon.ServiceError) {
		return true, nil
	}
	suite.sharingService.shareFunc = func(
		_ context.Context, _ sharing.ResourceType, resourceID, owningOUID, actingOUID string,
		_ sharing.SharePolicy,
	) ([]sharing.Grant, *tidcommon.ServiceError) {
		suite.Equal("rs1", resourceID)
		suite.Equal("owner-ou", owningOUID, "owning OU is always the resource server's own OU")
		suite.Equal("sharee-ou", actingOUID, "acting OU is the resharing sharee")
		return []sharing.Grant{{ID: "grant-1"}}, nil
	}

	result, svcErr := suite.service.ShareResourceServer(
		testOwnOUContext("sharee-ou"), "rs1", ShareRequest{OUID: "sharee-ou", AllChildren: true})
	suite.Nil(svcErr)
	suite.Len(result, 1)
}

// --- GetResourceServersForOU: the OU-confined listing ---

func (suite *ResourceAuthzTestSuite) TestGetResourceServersForOU_RejectsForeignOU() {
	// No store expectations: the scope check must run before any lookup.
	result, svcErr := suite.service.GetResourceServersForOU(testOwnOUContext("ou-1"), "ou-2", 30, 0)
	suite.Nil(result)
	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorResourceOutsideOwnOUScope.Code, svcErr.Code)
}

func (suite *ResourceAuthzTestSuite) TestGetResourceServersForOU_CombinesOwnedAndShared() {
	suite.mockStore.On("GetResourceServerListCountByOUID", mock.Anything, "ou-1").Return(1, nil)
	suite.mockStore.On("GetResourceServerListByOUID", mock.Anything, "ou-1", 1, 0).
		Return([]providers.ResourceServer{{ID: "rs-own", OUID: "ou-1"}}, nil)
	suite.sharingService.listSharedResourceIDsFunc = func(
		_ context.Context, resourceType sharing.ResourceType, ouID string,
	) ([]string, *tidcommon.ServiceError) {
		suite.Equal(resourceServerSharingType, resourceType)
		suite.Equal("ou-1", ouID)
		return []string{"rs-shared"}, nil
	}
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs-shared").
		Return(providers.ResourceServer{ID: "rs-shared", OUID: "owner-ou"}, nil)

	result, svcErr := suite.service.GetResourceServersForOU(testOwnOUContext("ou-1"), "ou-1", 30, 0)
	suite.Nil(svcErr)
	suite.Require().NotNil(result)
	suite.Equal(2, result.TotalResults)
	ids := []string{result.ResourceServers[0].ID, result.ResourceServers[1].ID}
	suite.ElementsMatch([]string{"rs-own", "rs-shared"}, ids)
}

// A grant left pointing at a deleted resource server must be skipped, not fail the listing.
func (suite *ResourceAuthzTestSuite) TestGetResourceServersForOU_SkipsStaleGrant() {
	suite.mockStore.On("GetResourceServerListCountByOUID", mock.Anything, "ou-1").Return(0, nil)
	suite.mockStore.On("GetResourceServerListByOUID", mock.Anything, "ou-1", 0, 0).
		Return([]providers.ResourceServer{}, nil)
	suite.sharingService.listSharedResourceIDsFunc = func(
		_ context.Context, _ sharing.ResourceType, _ string,
	) ([]string, *tidcommon.ServiceError) {
		return []string{"rs-deleted"}, nil
	}
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs-deleted").
		Return(providers.ResourceServer{}, errResourceServerNotFound)

	result, svcErr := suite.service.GetResourceServersForOU(testOwnOUContext("ou-1"), "ou-1", 30, 0)
	suite.Nil(svcErr)
	suite.Require().NotNil(result)
	suite.Equal(0, result.TotalResults)
}

// A root caller may ask about any OU, so the confinement check must not fire for it.
func (suite *ResourceAuthzTestSuite) TestGetResourceServersForOU_RootMayQueryAnyOU() {
	suite.mockStore.On("GetResourceServerListCountByOUID", mock.Anything, "ou-2").Return(0, nil)
	suite.mockStore.On("GetResourceServerListByOUID", mock.Anything, "ou-2", 0, 0).
		Return([]providers.ResourceServer{}, nil)
	suite.sharingService.listSharedResourceIDsFunc = func(
		_ context.Context, _ sharing.ResourceType, _ string,
	) ([]string, *tidcommon.ServiceError) {
		return nil, nil
	}

	result, svcErr := suite.service.GetResourceServersForOU(testRootContext(), "ou-2", 30, 0)
	suite.Nil(svcErr)
	suite.Require().NotNil(result)
	suite.Equal(0, result.TotalResults)
}
