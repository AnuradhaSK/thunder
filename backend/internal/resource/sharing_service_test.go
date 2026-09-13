// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"context"
	"errors"
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

func TestMain(m *testing.M) {
	security.InitSystemPermissions("")
	m.Run()
}

// testRootContext returns a context carrying the root system OAuth scope, so tests that predate
// the system:resource-servers OU-scoping checks (requireOwnOUScope/RequireVisibility/
// sharing.RequireOwnership) exercise their intended behavior without needing every test to
// construct a specific caller OU — a root-scoped caller is always unrestricted. Tests that
// specifically exercise own-OU-scope behavior build their own narrower context instead.
func testRootContext() context.Context {
	authCtx := security.NewSecurityContextForTest("test-subject", "test-ou", "test-token", []string{"system"}, nil)
	return security.WithSecurityContextTest(context.Background(), authCtx)
}

// testOwnOUContext returns a context carrying ouID as the caller's own OU claim, with no root
// permission — i.e. a system:resource-servers-only caller confined to ouID.
func testOwnOUContext(ouID string) context.Context {
	authCtx := security.NewSecurityContextForTest("test-subject", ouID, "test-token", nil, nil)
	return security.WithSecurityContextTest(context.Background(), authCtx)
}

// testSharedRSID is the fixture resource server the ValidatePermissions tests below all address.
const testSharedRSID = "rs1"

// testDescendantResourceID is a fixture resource ID reused across the cascade share/unshare
// tests in this file to stand in for a resource beneath the resource server being shared.
const testDescendantResourceID = "resource-node-1"

// SharingServiceTestSuite exercises the resource-tree sharing orchestration in sharing.go: the
// organization unit half of ValidatePermissions (the compound RBAC check), cascade share/unshare,
// and auto-inherit on creation.
type SharingServiceTestSuite struct {
	suite.Suite
	mockStore      *resourceStoreInterfaceMock
	mockOU         *oumock.OrganizationUnitServiceInterfaceMock
	sharingService *fakeSharingService
	service        *resourceService
}

func TestSharingServiceTestSuite(t *testing.T) {
	suite.Run(t, new(SharingServiceTestSuite))
}

func (suite *SharingServiceTestSuite) SetupTest() {
	testConfig := &config.Config{}
	config.ResetServerRuntime()
	err := config.InitializeServerRuntime("/tmp/test", testConfig)
	require.NoError(suite.T(), err)

	suite.mockStore = newResourceStoreInterfaceMock(suite.T())
	suite.mockOU = new(oumock.OrganizationUnitServiceInterfaceMock)
	suite.sharingService = &fakeSharingService{}
	svc, err := newResourceService(suite.mockOU, suite.mockStore, &fakeTransactioner{}, suite.sharingService)
	require.NoError(suite.T(), err)
	suite.service = svc.(*resourceService)
}

func (suite *SharingServiceTestSuite) TearDownTest() {
	config.ResetServerRuntime()
}

// --- ValidatePermissions, organization unit half ---
//
// These cover ValidatePermissions when an ouID is supplied, which is what replaced the separate
// visibility-filtering method: the permissions it reports back are the ones the organization unit
// may not use, whether because they do not exist or because they were never granted to it.

// expectPermissionsExist mocks the existence half of ValidatePermissions on testSharedRSID as "all
// of them exist", so a test asserts purely on what the organization unit check adds.
func (suite *SharingServiceTestSuite) expectPermissionsExist(permissions []string) {
	suite.mockStore.On("ValidatePermissions", mock.Anything, testSharedRSID, permissions).
		Return([]string{}, nil)
}

func (suite *SharingServiceTestSuite) TestValidatePermissions_EmptyInput() {
	invalid, svcErr := suite.service.ValidatePermissions(context.Background(), "rs1", []string{}, "ou1")
	suite.Nil(svcErr)
	suite.Equal([]string{}, invalid)
}

func (suite *SharingServiceTestSuite) TestValidatePermissions_RootPermissionAlwaysUsable() {
	root := security.GetSystemRootPermission()

	// No IsShared/store call should be needed: the server is never even looked up when every
	// requested permission is the bare root permission.
	invalid, svcErr := suite.service.ValidatePermissions(
		context.Background(), "rs1", []string{root}, "ou-unrelated",
	)
	suite.Nil(svcErr)
	suite.Equal([]string{}, invalid)
}

func (suite *SharingServiceTestSuite) TestValidatePermissions_ResourceServerNotFound() {
	root := security.GetSystemRootPermission()
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{}, errResourceServerNotFound)

	invalid, svcErr := suite.service.ValidatePermissions(
		context.Background(), "rs1", []string{root, "perm1"}, "ou1",
	)
	suite.Nil(svcErr)
	// The root permission stays usable; the rest are not, since the server that would define them
	// doesn't exist.
	suite.Equal([]string{"perm1"}, invalid)
}

func (suite *SharingServiceTestSuite) TestValidatePermissions_ResourceServerStoreError() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{}, errors.New("db down"))

	invalid, svcErr := suite.service.ValidatePermissions(
		context.Background(), "rs1", []string{"perm1"}, "ou1",
	)
	suite.Nil(invalid)
	suite.NotNil(svcErr)
	suite.Equal(tidcommon.InternalServerError.Code, svcErr.Code)
}

func (suite *SharingServiceTestSuite) TestValidatePermissions_OwnerUsesEverything() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "ou1"}, nil)
	suite.expectPermissionsExist([]string{"perm1", "perm2"})

	invalid, svcErr := suite.service.ValidatePermissions(
		context.Background(), "rs1", []string{"perm1", "perm2"}, "ou1",
	)
	suite.Nil(svcErr)
	suite.Empty(invalid)
}

// No ouID means no organization unit narrowing at all: the store's existence answer is returned
// verbatim and the sharing service is never consulted. This is the pre-existing behavior every
// caller that has no single acting organization unit still relies on.
func (suite *SharingServiceTestSuite) TestValidatePermissions_NoOUSkipsSharingEntirely() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou"}, nil)
	suite.mockStore.On("ValidatePermissions", mock.Anything, "rs1", []string{"perm1", "gone"}).
		Return([]string{"gone"}, nil)
	suite.sharingService.isSharedFunc = func(
		_ context.Context, _ sharing.ResourceType, _, _ string,
	) (bool, *tidcommon.ServiceError) {
		suite.Fail("sharing must not be consulted when no organization unit is given")
		return false, nil
	}

	invalid, svcErr := suite.service.ValidatePermissions(
		context.Background(), "rs1", []string{"perm1", "gone"}, "",
	)
	suite.Nil(svcErr)
	suite.Equal([]string{"gone"}, invalid)
}

func (suite *SharingServiceTestSuite) TestValidatePermissions_ServerNotGrantedToOU() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou"}, nil)
	suite.expectPermissionsExist([]string{"perm1"})
	suite.sharingService.isSharedFunc = func(
		_ context.Context, resourceType sharing.ResourceType, resourceID, ouID string,
	) (bool, *tidcommon.ServiceError) {
		suite.Equal(resourceServerSharingType, resourceType)
		suite.Equal("rs1", resourceID)
		suite.Equal("other-ou", ouID)
		return false, nil
	}

	invalid, svcErr := suite.service.ValidatePermissions(
		context.Background(), "rs1", []string{"perm1"}, "other-ou",
	)
	suite.Nil(svcErr)
	suite.Equal([]string{"perm1"}, invalid)
}

func (suite *SharingServiceTestSuite) TestValidatePermissions_ServerGrantedNodeVisibleAndNot() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou"}, nil)
	suite.expectPermissionsExist([]string{"books.view", "books.create"})
	suite.sharingService.isSharedFunc = func(
		_ context.Context, resourceType sharing.ResourceType, resourceID, ouID string,
	) (bool, *tidcommon.ServiceError) {
		if resourceType == resourceServerSharingType {
			return true, nil
		}
		// Node-level visibility: only the "view" action is granted, "create" is withheld.
		return resourceID == "action-view", nil
	}
	suite.mockStore.On("ResolvePermissionNode", mock.Anything, "rs1", "books.view").
		Return("action-view", "action", true, nil)
	suite.mockStore.On("ResolvePermissionNode", mock.Anything, "rs1", "books.create").
		Return("action-create", "action", true, nil)

	invalid, svcErr := suite.service.ValidatePermissions(
		context.Background(), "rs1", []string{"books.view", "books.create"}, "other-ou",
	)
	suite.Nil(svcErr)
	suite.Equal([]string{"books.create"}, invalid)
}

// A permission the store already rejected must not be reported a second time by the organization
// unit check, which would make the caller's "how many are unusable" count wrong.
func (suite *SharingServiceTestSuite) TestValidatePermissions_NonExistentNotReportedTwice() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou"}, nil)
	suite.mockStore.On("ValidatePermissions", mock.Anything, "rs1", []string{"gone", "withheld"}).
		Return([]string{"gone"}, nil)
	suite.sharingService.isSharedFunc = func(
		_ context.Context, resourceType sharing.ResourceType, _, _ string,
	) (bool, *tidcommon.ServiceError) {
		return resourceType == resourceServerSharingType, nil
	}
	suite.mockStore.On("ResolvePermissionNode", mock.Anything, "rs1", "withheld").
		Return("action-withheld", "action", true, nil)

	invalid, svcErr := suite.service.ValidatePermissions(
		context.Background(), "rs1", []string{"gone", "withheld"}, "other-ou",
	)
	suite.Nil(svcErr)
	suite.Equal([]string{"gone", "withheld"}, invalid)
}

func (suite *SharingServiceTestSuite) TestValidatePermissions_PermissionNodeNotFoundIsUnusable() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou"}, nil)
	suite.expectPermissionsExist([]string{"unknown.perm"})
	suite.sharingService.isSharedFunc = func(
		_ context.Context, _ sharing.ResourceType, _, _ string,
	) (bool, *tidcommon.ServiceError) {
		return true, nil
	}
	suite.mockStore.On("ResolvePermissionNode", mock.Anything, "rs1", "unknown.perm").
		Return("", "", false, nil)

	invalid, svcErr := suite.service.ValidatePermissions(
		context.Background(), "rs1", []string{"unknown.perm"}, "other-ou",
	)
	suite.Nil(svcErr)
	suite.Equal([]string{"unknown.perm"}, invalid)
}

func (suite *SharingServiceTestSuite) TestValidatePermissions_ResolvePermissionNodeStoreError() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou"}, nil)
	suite.expectPermissionsExist([]string{"books.view"})
	suite.sharingService.isSharedFunc = func(
		_ context.Context, _ sharing.ResourceType, _, _ string,
	) (bool, *tidcommon.ServiceError) {
		return true, nil
	}
	suite.mockStore.On("ResolvePermissionNode", mock.Anything, "rs1", "books.view").
		Return("", "", false, errors.New("db down"))

	invalid, svcErr := suite.service.ValidatePermissions(
		context.Background(), "rs1", []string{"books.view"}, "other-ou",
	)
	suite.Nil(invalid)
	suite.NotNil(svcErr)
	suite.Equal(tidcommon.InternalServerError.Code, svcErr.Code)
}

// --- Auto-inherit on creation (inheritGrants) ---

func (suite *SharingServiceTestSuite) TestInheritGrants_ReplaysEveryExportedGrant() {
	policy := sharing.SharePolicy{AllChildren: true}
	suite.sharingService.exportGrantsFunc = func(
		_ context.Context, resourceType sharing.ResourceType, resourceID string,
	) ([]sharing.ReplayableGrant, *tidcommon.ServiceError) {
		suite.Equal(resourceServerSharingType, resourceType)
		suite.Equal("rs1", resourceID)
		return []sharing.ReplayableGrant{{ActingOUID: "owner-ou", Policy: policy}}, nil
	}
	var sharedCalls []sharing.ResourceType
	suite.sharingService.shareFunc = func(
		_ context.Context, resourceType sharing.ResourceType, resourceID, owningOUID, actingOUID string,
		p sharing.SharePolicy,
	) ([]sharing.Grant, *tidcommon.ServiceError) {
		sharedCalls = append(sharedCalls, resourceType)
		suite.Equal(resourceNodeSharingType, resourceType)
		suite.Equal("res-new", resourceID)
		suite.Equal("owner-ou", owningOUID)
		suite.Equal("owner-ou", actingOUID)
		suite.Equal(policy, p)
		return []sharing.Grant{{ID: "grant1"}}, nil
	}

	svcErr := suite.service.inheritGrants(
		context.Background(), resourceServerSharingType, "rs1", resourceNodeSharingType, "res-new", "owner-ou",
	)
	suite.Nil(svcErr)
	suite.Equal([]sharing.ResourceType{resourceNodeSharingType}, sharedCalls)
}

func (suite *SharingServiceTestSuite) TestInheritGrants_NoGrantsIsNoOp() {
	suite.sharingService.exportGrantsFunc = func(
		_ context.Context, _ sharing.ResourceType, _ string,
	) ([]sharing.ReplayableGrant, *tidcommon.ServiceError) {
		return nil, nil
	}
	// shareFunc deliberately left nil: any call panics via fakeSharingService, proving Share is
	// never invoked when there's nothing to replay.
	svcErr := suite.service.inheritGrants(
		context.Background(), resourceServerSharingType, "rs1", resourceNodeSharingType, "res-new", "owner-ou",
	)
	suite.Nil(svcErr)
}

func (suite *SharingServiceTestSuite) TestInheritGrants_ExportGrantsErrorPropagates() {
	expected := &tidcommon.ServiceError{Code: "SOME_ERROR"}
	suite.sharingService.exportGrantsFunc = func(
		_ context.Context, _ sharing.ResourceType, _ string,
	) ([]sharing.ReplayableGrant, *tidcommon.ServiceError) {
		return nil, expected
	}
	svcErr := suite.service.inheritGrants(
		context.Background(), resourceServerSharingType, "rs1", resourceNodeSharingType, "res-new", "owner-ou",
	)
	suite.Equal(expected, svcErr)
}

// --- Cascade share (ShareResourceServer / ShareResource / ShareAction) ---

func (suite *SharingServiceTestSuite) TestShareResourceServer_CascadesToResourcesAndActions() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou"}, nil)
	suite.mockStore.On("GetResourceListCount", mock.Anything, "rs1").Return(1, nil)
	suite.mockStore.On("GetResourceList", mock.Anything, "rs1", 1, 0).
		Return([]providers.Resource{{ID: testDescendantResourceID}}, nil)
	// Top-level actions (resourceID nil).
	suite.mockStore.On("GetActionListCount", mock.Anything, "rs1", (*string)(nil), providers.ActionKind("")).
		Return(0, nil)
	// Actions under res1.
	suite.mockStore.On(
		"GetActionListCount", mock.Anything, "rs1", mock.MatchedBy(func(id *string) bool {
			return id != nil && *id == testDescendantResourceID
		}), providers.ActionKind(""),
	).Return(1, nil)
	suite.mockStore.On(
		"GetActionList", mock.Anything, "rs1", mock.MatchedBy(func(id *string) bool {
			return id != nil && *id == testDescendantResourceID
		}), providers.ActionKind(""), 1, 0,
	).Return([]providers.Action{{ID: "act1"}}, nil)

	var sharedNodes []string
	suite.sharingService.shareFunc = func(
		_ context.Context, resourceType sharing.ResourceType, resourceID, owningOUID, actingOUID string,
		_ sharing.SharePolicy,
	) ([]sharing.Grant, *tidcommon.ServiceError) {
		suite.Equal("owner-ou", owningOUID)
		suite.Equal("owner-ou", actingOUID)
		sharedNodes = append(sharedNodes, string(resourceType)+":"+resourceID)
		return []sharing.Grant{{ID: "grant-" + resourceID, Stage: sharing.StageShare}}, nil
	}

	result, svcErr := suite.service.ShareResourceServer(testRootContext(), "rs1", ShareRequest{AllChildren: true})
	suite.Nil(svcErr)
	suite.ElementsMatch(
		[]string{"resource_server:rs1", "resource:resource-node-1", "action:act1"}, sharedNodes,
	)
	suite.Len(result, 3)
}

func (suite *SharingServiceTestSuite) TestShareResourceServer_ExcludesRequestedNodeIDs() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou"}, nil)
	suite.mockStore.On("GetResourceListCount", mock.Anything, "rs1").Return(1, nil)
	suite.mockStore.On("GetResourceList", mock.Anything, "rs1", 1, 0).
		Return([]providers.Resource{{ID: testDescendantResourceID}}, nil)
	suite.mockStore.On("GetActionListCount", mock.Anything, "rs1", (*string)(nil), providers.ActionKind("")).
		Return(0, nil)
	suite.mockStore.On(
		"GetActionListCount", mock.Anything, "rs1", mock.MatchedBy(func(id *string) bool {
			return id != nil && *id == testDescendantResourceID
		}), providers.ActionKind(""),
	).Return(0, nil)

	var sharedNodes []string
	suite.sharingService.shareFunc = func(
		_ context.Context, resourceType sharing.ResourceType, resourceID, _, _ string, _ sharing.SharePolicy,
	) ([]sharing.Grant, *tidcommon.ServiceError) {
		sharedNodes = append(sharedNodes, string(resourceType)+":"+resourceID)
		return []sharing.Grant{{ID: "grant-" + resourceID}}, nil
	}

	req := ShareRequest{AllChildren: true, ExcludedNodeIDs: []string{testDescendantResourceID}}
	result, svcErr := suite.service.ShareResourceServer(testRootContext(), "rs1", req)
	suite.Nil(svcErr)
	// The descendant resource is excluded from the cascade, so only the resource server itself is
	// shared.
	suite.Equal([]string{"resource_server:rs1"}, sharedNodes)
	suite.Len(result, 1)
}

func (suite *SharingServiceTestSuite) TestShareResourceServer_NotFound() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{}, errResourceServerNotFound)

	result, svcErr := suite.service.ShareResourceServer(context.Background(), "rs1", ShareRequest{AllChildren: true})
	suite.Nil(result)
	suite.NotNil(svcErr)
	suite.Equal(ErrorResourceServerNotFound.Code, svcErr.Code)
}

func (suite *SharingServiceTestSuite) TestShareAction_NeverCascades() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou"}, nil)

	// No GetResourceListCount/GetActionListCount expectations set: if ShareAction cascaded, the
	// mock would panic on an unexpected call.
	suite.sharingService.shareFunc = func(
		_ context.Context, resourceType sharing.ResourceType, resourceID, _, _ string, _ sharing.SharePolicy,
	) ([]sharing.Grant, *tidcommon.ServiceError) {
		suite.Equal(actionSharingType, resourceType)
		suite.Equal("act1", resourceID)
		return []sharing.Grant{{ID: "grant1"}}, nil
	}

	result, svcErr := suite.service.ShareAction(
		testRootContext(), "rs1", nil, "act1", ShareRequest{AllChildren: true},
	)
	suite.Nil(svcErr)
	suite.Len(result, 1)
}

// --- Cascade unshare ---

func (suite *SharingServiceTestSuite) TestUnshareResourceServerGrant_CascadesMatchingDescendantGrants() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou"}, nil)
	suite.mockStore.On("GetResourceListCount", mock.Anything, "rs1").Return(1, nil)
	suite.mockStore.On("GetResourceList", mock.Anything, "rs1", 1, 0).
		Return([]providers.Resource{{ID: testDescendantResourceID}}, nil)
	suite.mockStore.On("GetActionListCount", mock.Anything, "rs1", (*string)(nil), providers.ActionKind("")).
		Return(0, nil)
	suite.mockStore.On(
		"GetActionListCount", mock.Anything, "rs1", mock.MatchedBy(func(id *string) bool {
			return id != nil && *id == testDescendantResourceID
		}), providers.ActionKind(""),
	).Return(0, nil)

	targetGrant := sharing.Grant{
		ID: "grant-rs1", TargetScope: sharing.TargetScopeAllChildren, TargetOUID: "owner-ou",
	}
	matchingDescendantGrant := sharing.Grant{
		ID: "grant-res1-matching", TargetScope: sharing.TargetScopeAllChildren, TargetOUID: "owner-ou",
	}
	nonMatchingDescendantGrant := sharing.Grant{
		ID: "grant-res1-other", TargetScope: sharing.TargetScopeOU, TargetOUID: "some-other-ou",
	}

	suite.sharingService.listGrantsFunc = func(
		_ context.Context, resourceType sharing.ResourceType, resourceID string,
	) ([]sharing.Grant, *tidcommon.ServiceError) {
		if resourceType == resourceServerSharingType && resourceID == "rs1" {
			return []sharing.Grant{targetGrant}, nil
		}
		if resourceType == resourceNodeSharingType && resourceID == testDescendantResourceID {
			return []sharing.Grant{matchingDescendantGrant, nonMatchingDescendantGrant}, nil
		}
		return nil, nil
	}
	var unsharedIDs []string
	suite.sharingService.unshareFunc = func(_ context.Context, grantID string) *tidcommon.ServiceError {
		unsharedIDs = append(unsharedIDs, grantID)
		return nil
	}

	svcErr := suite.service.UnshareResourceServerGrant(testRootContext(), "rs1", "grant-rs1")
	suite.Nil(svcErr)
	suite.ElementsMatch([]string{"grant-rs1", "grant-res1-matching"}, unsharedIDs)
}

func (suite *SharingServiceTestSuite) TestUnshareResourceServerGrant_GrantNotFound() {
	suite.mockStore.On("GetResourceServer", mock.Anything, "rs1").
		Return(providers.ResourceServer{ID: "rs1", OUID: "owner-ou"}, nil)
	suite.sharingService.listGrantsFunc = func(
		_ context.Context, _ sharing.ResourceType, _ string,
	) ([]sharing.Grant, *tidcommon.ServiceError) {
		return []sharing.Grant{{ID: "some-other-grant"}}, nil
	}

	svcErr := suite.service.UnshareResourceServerGrant(testRootContext(), "rs1", "missing-grant")
	suite.NotNil(svcErr)
	suite.Equal(sharing.ErrorGrantNotFound.Code, svcErr.Code)
}

// --- sameOUSelection / sameStringSet ---

func (suite *SharingServiceTestSuite) TestSameOUSelection() {
	testCases := []struct {
		name     string
		a, b     sharing.Grant
		expected bool
	}{
		{
			name:     "DifferentTargetScope",
			a:        sharing.Grant{TargetScope: sharing.TargetScopeOU, TargetOUID: "ou1"},
			b:        sharing.Grant{TargetScope: sharing.TargetScopeAllChildren, TargetOUID: "ou1"},
			expected: false,
		},
		{
			name:     "DifferentTargetOUID",
			a:        sharing.Grant{TargetScope: sharing.TargetScopeOU, TargetOUID: "ou1"},
			b:        sharing.Grant{TargetScope: sharing.TargetScopeOU, TargetOUID: "ou2"},
			expected: false,
		},
		{
			name:     "SameNonBlanketScope",
			a:        sharing.Grant{TargetScope: sharing.TargetScopeOU, TargetOUID: "ou1"},
			b:        sharing.Grant{TargetScope: sharing.TargetScopeOU, TargetOUID: "ou1"},
			expected: true,
		},
		{
			name: "SameAllRootsSameExclusions",
			a: sharing.Grant{
				TargetScope: sharing.TargetScopeAllRoots, ExcludedOUIDs: []string{"ou2", "ou3"},
			},
			b: sharing.Grant{
				TargetScope: sharing.TargetScopeAllRoots, ExcludedOUIDs: []string{"ou3", "ou2"},
			},
			expected: true,
		},
		{
			name: "SameAllChildrenDifferentExclusions",
			a: sharing.Grant{
				TargetScope: sharing.TargetScopeAllChildren, TargetOUID: "anchor",
				ExcludedOUIDs: []string{"ou2"},
			},
			b: sharing.Grant{
				TargetScope: sharing.TargetScopeAllChildren, TargetOUID: "anchor",
				ExcludedOUIDs: []string{"ou3"},
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			suite.Equal(tc.expected, sameOUSelection(tc.a, tc.b))
		})
	}
}

// --- onNodeUnshared (SharingHooks.OnUnshare for resource/action nodes) ---

// fakeRolePermissionRevoker is a test double for RolePermissionRevoker.
type fakeRolePermissionRevoker struct {
	revokeFunc func(ctx context.Context, ouID, resourceServerID, permission string) (int, error)
	calls      []fakeRevokeCall
}

type fakeRevokeCall struct {
	ouID, resourceServerID, permission string
}

func (f *fakeRolePermissionRevoker) RevokeRolePermissionForOU(
	ctx context.Context, ouID, resourceServerID, permission string,
) (int, error) {
	f.calls = append(f.calls, fakeRevokeCall{ouID, resourceServerID, permission})
	if f.revokeFunc != nil {
		return f.revokeFunc(ctx, ouID, resourceServerID, permission)
	}
	return 0, nil
}

func (suite *SharingServiceTestSuite) TestOnNodeUnshared_NoRevokerConfigured() {
	// suite.service never had SetRolePermissionRevoker called: this must be a documented no-op,
	// not a panic, and must not even attempt to resolve the node's permission.
	err := suite.service.onNodeUnshared(context.Background(), "resource", "res-1", "ou-1")
	suite.NoError(err)
}

func (suite *SharingServiceTestSuite) TestOnNodeUnshared_NodeNotFound() {
	revoker := &fakeRolePermissionRevoker{}
	suite.service.SetRolePermissionRevoker(revoker)
	suite.mockStore.On("ResolveNodePermission", mock.Anything, "resource", "res-1").
		Return("", "", false, nil)

	err := suite.service.onNodeUnshared(context.Background(), "resource", "res-1", "ou-1")
	suite.NoError(err)
	suite.Empty(revoker.calls, "revoker must not be called when the node no longer exists")
}

func (suite *SharingServiceTestSuite) TestOnNodeUnshared_ResolveStoreError() {
	revoker := &fakeRolePermissionRevoker{}
	suite.service.SetRolePermissionRevoker(revoker)
	suite.mockStore.On("ResolveNodePermission", mock.Anything, "action", "act-1").
		Return("", "", false, errors.New("db down"))

	err := suite.service.onNodeUnshared(context.Background(), "action", "act-1", "ou-1")
	suite.Error(err)
	suite.Empty(revoker.calls)
}

func (suite *SharingServiceTestSuite) TestOnNodeUnshared_ResourceKind_CallsRevoker() {
	revoker := &fakeRolePermissionRevoker{}
	suite.service.SetRolePermissionRevoker(revoker)
	suite.mockStore.On("ResolveNodePermission", mock.Anything, "resource", "res-1").
		Return("rs1", "books", true, nil)

	err := suite.service.onNodeUnshared(context.Background(), "resource", "res-1", "ou-1")
	suite.NoError(err)
	suite.Equal([]fakeRevokeCall{{ouID: "ou-1", resourceServerID: "rs1", permission: "books"}}, revoker.calls)
}

func (suite *SharingServiceTestSuite) TestOnNodeUnshared_ActionKind_CallsRevoker() {
	revoker := &fakeRolePermissionRevoker{}
	suite.service.SetRolePermissionRevoker(revoker)
	suite.mockStore.On("ResolveNodePermission", mock.Anything, "action", "act-1").
		Return("rs1", "books:create", true, nil)

	err := suite.service.onNodeUnshared(context.Background(), "action", "act-1", "ou-1")
	suite.NoError(err)
	suite.Equal(
		[]fakeRevokeCall{{ouID: "ou-1", resourceServerID: "rs1", permission: "books:create"}}, revoker.calls,
	)
}

func (suite *SharingServiceTestSuite) TestOnNodeUnshared_RevokerErrorPropagates() {
	revoker := &fakeRolePermissionRevoker{
		revokeFunc: func(_ context.Context, _, _, _ string) (int, error) {
			return 0, errors.New("delete failed")
		},
	}
	suite.service.SetRolePermissionRevoker(revoker)
	suite.mockStore.On("ResolveNodePermission", mock.Anything, "resource", "res-1").
		Return("rs1", "books", true, nil)

	err := suite.service.onNodeUnshared(context.Background(), "resource", "res-1", "ou-1")
	suite.Error(err)
}

// --- resourceNodeTypeDeclaration/actionTypeDeclaration.OnUnshare delegate correctly ---

func (suite *SharingServiceTestSuite) TestNodeTypeDeclarationOnUnshare_DelegatesToService() {
	revoker := &fakeRolePermissionRevoker{}
	suite.service.SetRolePermissionRevoker(revoker)
	suite.mockStore.On("ResolveNodePermission", mock.Anything, "resource", "res-1").
		Return("rs1", "books", true, nil)

	decl := newResourceNodeTypeDeclaration(suite.service)
	hooks, ok := decl.(sharing.SharingHooks)
	suite.Require().True(ok)
	suite.NoError(hooks.OnUnshare(context.Background(), "res-1", "ou-1"))
	suite.Len(revoker.calls, 1)
}

func (suite *SharingServiceTestSuite) TestActionTypeDeclarationOnUnshare_DelegatesToService() {
	revoker := &fakeRolePermissionRevoker{}
	suite.service.SetRolePermissionRevoker(revoker)
	suite.mockStore.On("ResolveNodePermission", mock.Anything, "action", "act-1").
		Return("rs1", "books:view", true, nil)

	decl := newActionTypeDeclaration(suite.service)
	hooks, ok := decl.(sharing.SharingHooks)
	suite.Require().True(ok)
	suite.NoError(hooks.OnUnshare(context.Background(), "act-1", "ou-1"))
	suite.Len(revoker.calls, 1)
}
