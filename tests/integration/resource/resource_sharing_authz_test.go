// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/thunder-id/thunderid/tests/integration/testutils"
)

// ResourceSharingAuthzTestSuite proves the actual point of this feature: that
// resourceService.FilterVisiblePermissions is wired into real permission resolution, reached
// through real client_credentials token issuance, not just unit-testable in isolation.
//
// Fixture topology:
//
//	ownerOU  owns bookingsRS ("bookings" resource, "view"/"create" actions) and rootPermRS (a
//	         top-level "system" resource reproducing the literal deployment root permission
//	         string on a resource server this suite fully controls, rather than touching the
//	         real bootstrap "System" resource server).
//	shareeOU has bookingsRS itself cascade-shared to it (which fans out to "bookings" and both
//	         its actions — the server-level share is required: FilterVisiblePermissions' §4.2
//	         step 3 gate makes nothing under a resource server visible until the server itself is
//	         shared) at fixture build time, immediately followed by revoking only the "create"
//	         action's own grant — simulating a resource unshared *after* a role naming it was
//	         already created, which is the scenario the mandatory read-time enforcement (as
//	         opposed to the write-time check alone) exists to catch. shareeOU never receives any
//	         share of rootPermRS at all.
//
//	shareeApp is assigned two roles: one naming both "bookings:view" and "bookings:create" (valid
//	at creation time, since both were visible then), and one naming the bare root permission
//	"system" on rootPermRS (valid despite zero sharing, because the root permission is a
//	categorical bypass, never a grant).
//	ownerApp is assigned a role naming the same two bookings permissions, owned by ownerOU itself.
type ResourceSharingAuthzTestSuite struct {
	suite.Suite

	ownerOUID  string
	shareeOUID string

	bookingsRSID   string
	bookingsID     string
	viewActionID   string
	createActionID string
	// bookingsGrantID is the resource-server-level cascade grant sharing bookingsRSID (and,
	// originally, "bookings" and both its actions) to shareeOU; unsharing it at teardown cascades
	// to "bookings" and "view" as well ("create" was already unshared individually).
	bookingsGrantID string

	rootPermRSID string

	shareeAppID   string
	shareeRoleAID string
	shareeRoleBID string
	ownerAppID    string
	ownerRoleID   string
}

const (
	resSharingAuthzBookingsRSIdentifier = "https://res-sharing-authz.example.com/bookings"
	resSharingAuthzRootPermRSIdentifier = "https://res-sharing-authz.example.com/root-perm"

	resSharingAuthzShareeClientID     = "res_sharing_authz_sharee_client"
	resSharingAuthzShareeClientSecret = "res_sharing_authz_sharee_secret"
	resSharingAuthzOwnerClientID      = "res_sharing_authz_owner_client"
	resSharingAuthzOwnerClientSecret  = "res_sharing_authz_owner_secret"

	// resSharingAuthzRootPermission is the literal deployment root permission string
	// (security.GetSystemRootPermission()), which this deployment's default, empty
	// system_permission_prefix config resolves to "system".
	resSharingAuthzRootPermission = "system"
)

func TestResourceSharingAuthzTestSuite(t *testing.T) {
	suite.Run(t, new(ResourceSharingAuthzTestSuite))
}

func (suite *ResourceSharingAuthzTestSuite) SetupSuite() {
	ownerID, err := testutils.CreateOrganizationUnit(testutils.OrganizationUnit{
		Handle:      "res-sharing-authz-owner-ou",
		Name:        "Resource Sharing Authz Owner OU",
		Description: "Owns every resource server built by ResourceSharingAuthzTestSuite",
	})
	suite.Require().NoError(err, "Failed to create owner OU")
	suite.ownerOUID = ownerID

	shareeID, err := testutils.CreateOrganizationUnit(testutils.OrganizationUnit{
		Handle:      "res-sharing-authz-sharee-ou",
		Name:        "Resource Sharing Authz Sharee OU",
		Description: "Receives a partial share of bookingsRS; never receives any share of rootPermRS",
	})
	suite.Require().NoError(err, "Failed to create sharee OU")
	suite.shareeOUID = shareeID

	// --- bookingsRS: resource server, resource, and two actions, owned by ownerOU. ---
	rsID, err := createResourceServer(CreateResourceServerRequest{
		Name:       "Resource Sharing Authz Bookings RS",
		OUID:       suite.ownerOUID,
		Identifier: resSharingAuthzBookingsRSIdentifier,
	})
	suite.Require().NoError(err, "Failed to create bookings resource server")
	suite.bookingsRSID = rsID

	bookingsID, err := createResource(rsID, CreateResourceRequest{Name: "Bookings", Handle: "bookings"})
	suite.Require().NoError(err, "Failed to create bookings resource")
	suite.bookingsID = bookingsID

	viewID, err := createActionAtResource(rsID, bookingsID, CreateActionRequest{Name: "View", Handle: "view"})
	suite.Require().NoError(err, "Failed to create view action")
	suite.viewActionID = viewID

	createID, err := createActionAtResource(rsID, bookingsID, CreateActionRequest{Name: "Create", Handle: "create"})
	suite.Require().NoError(err, "Failed to create create action")
	suite.createActionID = createID

	// Cascade-share the whole resource server (and, transitively, "bookings" and both its
	// actions) to shareeOU. Sharing only the resource itself is not enough:
	// FilterVisiblePermissions's server-level gate (§4.2 step 3) requires the resource server
	// itself to be shared to an OU before any of its individual resources/actions can ever be
	// visible there.
	cascadeGrants, err := testutils.ShareResourceServer(rsID, map[string]interface{}{
		"rootOuIds": []string{suite.shareeOUID},
	})
	suite.Require().NoError(err, "Failed to cascade-share the bookings resource server to shareeOU")
	suite.Require().Len(cascadeGrants, 4, "server + bookings + view + create")
	for _, g := range cascadeGrants {
		if g.NodeType == "resource_server" && g.NodeID == rsID {
			suite.bookingsGrantID = g.ID
		}
	}
	suite.Require().NotEmpty(suite.bookingsGrantID, "must find the resource-server-level cascade grant")

	// --- rootPermRS: a resource server whose top-level resource's derived permission is the
	// literal deployment root permission string, never shared to shareeOU at all. ---
	rootPermRSID, err := createResourceServer(CreateResourceServerRequest{
		Name:       "Resource Sharing Authz Root Perm RS",
		OUID:       suite.ownerOUID,
		Identifier: resSharingAuthzRootPermRSIdentifier,
	})
	suite.Require().NoError(err, "Failed to create root-permission resource server")
	suite.rootPermRSID = rootPermRSID

	_, err = createResource(rootPermRSID, CreateResourceRequest{
		Name: "System", Handle: resSharingAuthzRootPermission,
	})
	suite.Require().NoError(err, "Failed to create the root-permission-shaped resource")

	// --- shareeApp, holding both roles below. ---
	shareeAppID, err := testutils.CreateApplication(testutils.Application{
		Name: "Resource Sharing Authz Sharee App",
		OUID: suite.shareeOUID,
		Type: "m2m",
		InboundAuthConfig: []map[string]interface{}{
			{
				"type": "oauth2",
				"config": map[string]interface{}{
					"clientId":                resSharingAuthzShareeClientID,
					"clientSecret":            resSharingAuthzShareeClientSecret,
					"grantTypes":              []string{"client_credentials"},
					"tokenEndpointAuthMethod": "client_secret_basic",
				},
			},
		},
	})
	suite.Require().NoError(err, "Failed to create sharee app")
	suite.shareeAppID = shareeAppID

	// Role A: names both bookings permissions. Valid at creation time, since "create" is still
	// shared at this point — its share is revoked immediately below.
	roleAID, err := testutils.CreateRole(testutils.Role{
		Name: "res-sharing-authz-sharee-role-a",
		OUID: suite.shareeOUID,
		Permissions: []testutils.ResourcePermissions{
			{ResourceServerID: rsID, Permissions: []string{"bookings:view", "bookings:create"}},
		},
		Assignments: []testutils.Assignment{{ID: shareeAppID, Type: "app"}},
	})
	suite.Require().NoError(err, "Failed to create sharee role A (both permissions must be visible at creation time)")
	suite.shareeRoleAID = roleAID

	// Now revoke only the "create" action's own grant, leaving "bookings" and "view" shared.
	// This reproduces the design's motivating scenario: a resource/action unshared *after* a role
	// naming it was created must stop being usable immediately, with no stale-permission window.
	createGrants, err := testutils.ListActionGrants(rsID, bookingsID, createID)
	suite.Require().NoError(err)
	suite.Require().Len(createGrants, 1, "the create action must have exactly the cascade-created grant at this point")
	suite.Require().NoError(testutils.UnshareActionGrant(rsID, bookingsID, createID, createGrants[0].ID),
		"Failed to revoke the create action's share")

	// Role B: names the bare root permission on a resource server never shared to shareeOU at
	// all. Valid at creation time only because the root permission is a categorical bypass.
	roleBID, err := testutils.CreateRole(testutils.Role{
		Name: "res-sharing-authz-sharee-role-b",
		OUID: suite.shareeOUID,
		Permissions: []testutils.ResourcePermissions{
			{ResourceServerID: rootPermRSID, Permissions: []string{resSharingAuthzRootPermission}},
		},
		Assignments: []testutils.Assignment{{ID: shareeAppID, Type: "app"}},
	})
	suite.Require().NoError(err, "Failed to create sharee role B (root permission must bypass sharing entirely)")
	suite.shareeRoleBID = roleBID

	// --- ownerApp, holding a role naming both bookings permissions from ownerOU itself. ---
	ownerAppID, err := testutils.CreateApplication(testutils.Application{
		Name: "Resource Sharing Authz Owner App",
		OUID: suite.ownerOUID,
		Type: "m2m",
		InboundAuthConfig: []map[string]interface{}{
			{
				"type": "oauth2",
				"config": map[string]interface{}{
					"clientId":                resSharingAuthzOwnerClientID,
					"clientSecret":            resSharingAuthzOwnerClientSecret,
					"grantTypes":              []string{"client_credentials"},
					"tokenEndpointAuthMethod": "client_secret_basic",
				},
			},
		},
	})
	suite.Require().NoError(err, "Failed to create owner app")
	suite.ownerAppID = ownerAppID

	ownerRoleID, err := testutils.CreateRole(testutils.Role{
		Name: "res-sharing-authz-owner-role",
		OUID: suite.ownerOUID,
		Permissions: []testutils.ResourcePermissions{
			{ResourceServerID: rsID, Permissions: []string{"bookings:view", "bookings:create"}},
		},
		Assignments: []testutils.Assignment{{ID: ownerAppID, Type: "app"}},
	})
	suite.Require().NoError(err, "Failed to create owner role")
	suite.ownerRoleID = ownerRoleID
}

func (suite *ResourceSharingAuthzTestSuite) TearDownSuite() {
	for _, id := range []string{suite.shareeRoleAID, suite.shareeRoleBID, suite.ownerRoleID} {
		if id != "" {
			if err := testutils.DeleteRole(id); err != nil {
				suite.T().Logf("Failed to delete role %s: %v", id, err)
			}
		}
	}
	for _, id := range []string{suite.shareeAppID, suite.ownerAppID} {
		if id != "" {
			if err := testutils.DeleteApplication(id); err != nil {
				suite.T().Logf("Failed to delete application %s: %v", id, err)
			}
		}
	}
	if suite.bookingsGrantID != "" {
		// Cascades to "bookings" and "view", the remaining descendant grants from the original
		// cascade share ("create" was already unshared individually above).
		if err := testutils.UnshareResourceServerGrant(suite.bookingsRSID, suite.bookingsGrantID); err != nil {
			suite.T().Logf("Failed to unshare bookings resource server grant: %v", err)
		}
	}
	if suite.bookingsRSID != "" {
		if err := testutils.DeleteResourceServerWithChildren(suite.bookingsRSID); err != nil {
			suite.T().Logf("Failed to delete bookings resource server: %v", err)
		}
	}
	if suite.rootPermRSID != "" {
		if err := testutils.DeleteResourceServerWithChildren(suite.rootPermRSID); err != nil {
			suite.T().Logf("Failed to delete root-permission resource server: %v", err)
		}
	}
	for _, id := range []string{suite.shareeOUID, suite.ownerOUID} {
		if id != "" {
			if err := testutils.DeleteOrganizationUnit(id); err != nil {
				suite.T().Logf("Failed to delete OU %s: %v", id, err)
			}
		}
	}
}

// requestCCToken requests a client_credentials token scoped to the given resource server
// identifier, mirroring oauth/token's cc_app_authz_test.go pattern.
func (suite *ResourceSharingAuthzTestSuite) requestCCToken(
	clientID, clientSecret, scope, resourceIdentifier string,
) (int, map[string]interface{}) {
	suite.T().Helper()

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if scope != "" {
		form.Set("scope", scope)
	}
	if resourceIdentifier != "" {
		form.Set("resource", resourceIdentifier)
	}

	req, err := http.NewRequest("POST", testServerURL+"/oauth2/token", strings.NewReader(form.Encode()))
	suite.Require().NoError(err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := testutils.GetHTTPClient().Do(req)
	suite.Require().NoError(err)
	defer resp.Body.Close()

	var body map[string]interface{}
	suite.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))
	return resp.StatusCode, body
}

// TestCompoundRBAC_UnsharedActionPermissionDroppedAtTokenIssuance proves behavior 6(a): a role
// naming a permission whose action was unshared after the role's creation has that permission
// silently dropped at real token issuance, while a permission still shared survives.
//
// This previously could not be proven through any real OAuth-issued token, since no production
// caller ever supplied a non-empty ouID to GetAuthorizedPermissionsByResourceServer:
// providers.AccessEvaluationRequest had no OU field, and toEngineAccessEvaluationsRequest
// (internal/authz/service.go) never populated engine.AccessEvaluationRequest.OUID. That gap is now
// fixed for the client_credentials and refresh_token grant handlers (both go through the shared
// buildAccessEvaluationsRequest, which now accepts and forwards an ouID). The interactive flow
// executor (internal/flow/executor/authz_executor.go) and AuthZEN still have their own, separate
// instances of the same gap and remain unfixed.
func (suite *ResourceSharingAuthzTestSuite) TestCompoundRBAC_UnsharedActionPermissionDroppedAtTokenIssuance() {
	status, body := suite.requestCCToken(
		resSharingAuthzShareeClientID, resSharingAuthzShareeClientSecret,
		"bookings:view bookings:create", resSharingAuthzBookingsRSIdentifier,
	)
	suite.Require().Equal(http.StatusOK, status, "token request must still succeed: %v", body)

	scopeStr, _ := body["scope"].(string)
	scopes := strings.Fields(scopeStr)
	suite.ElementsMatch([]string{"bookings:view"}, scopes,
		"bookings:create must be silently dropped since its share was revoked after the role was created")
}

// TestCompoundRBAC_RootPermissionBypassesSharing proves behavior 6(b): the bare deployment root
// permission is never subject to sharing visibility, even though rootPermRS was never shared to
// shareeOU at all — the root permission is exempted before any OU check runs (§4.2 step 1).
func (suite *ResourceSharingAuthzTestSuite) TestCompoundRBAC_RootPermissionBypassesSharing() {
	status, body := suite.requestCCToken(
		resSharingAuthzShareeClientID, resSharingAuthzShareeClientSecret,
		resSharingAuthzRootPermission, resSharingAuthzRootPermRSIdentifier,
	)
	suite.Require().Equal(http.StatusOK, status, "token request must succeed: %v", body)

	scopeStr, _ := body["scope"].(string)
	suite.Equal(resSharingAuthzRootPermission, scopeStr,
		"the root permission must be kept regardless of sharing state")
}

// TestOwnerAlwaysSeesOwnResourceServer proves behavior 8: the owning OU's own role keeps every
// permission under its own resource server regardless of sharing state, including the "create"
// action whose share to the (unrelated) sharee OU was revoked — the owner short-circuit (§4.2 step
// 2) keeps every permission for the resource server's own OU.
func (suite *ResourceSharingAuthzTestSuite) TestOwnerAlwaysSeesOwnResourceServer() {
	status, body := suite.requestCCToken(
		resSharingAuthzOwnerClientID, resSharingAuthzOwnerClientSecret,
		"bookings:view bookings:create", resSharingAuthzBookingsRSIdentifier,
	)
	suite.Require().Equal(http.StatusOK, status, "token request must succeed: %v", body)

	scopeStr, _ := body["scope"].(string)
	scopes := strings.Fields(scopeStr)
	suite.ElementsMatch([]string{"bookings:view", "bookings:create"}, scopes,
		"the owning OU must see everything under its own resource server unconditionally")
}

// TestWriteTimeDefense_CreateRoleRejectsPermissionNotVisibleToOU proves behavior 7's first call
// site: creating a role that names a permission not currently visible to its own OU is rejected
// at creation time with ROL-1025, not silently accepted and dropped later.
func (suite *ResourceSharingAuthzTestSuite) TestWriteTimeDefense_CreateRoleRejectsPermissionNotVisibleToOU() {
	roleID, err := testutils.CreateRole(testutils.Role{
		Name: "res-sharing-authz-write-time-create",
		OUID: suite.shareeOUID,
		Permissions: []testutils.ResourcePermissions{
			{ResourceServerID: suite.bookingsRSID, Permissions: []string{"bookings:create"}},
		},
	})
	if err == nil {
		// Defensive cleanup: this branch must never be reached, but avoid leaking a role fixture
		// if the assertion below fails.
		_ = testutils.DeleteRole(roleID)
	}
	suite.Require().Error(err, "creating a role naming an unshared permission must fail")
	suite.Contains(err.Error(), "ROL-1025")
}

// TestWriteTimeDefense_UpdateRoleRejectsPermissionNotVisibleToOU proves behavior 7's second call
// site: updating an existing role to add a permission not currently visible to its own OU is
// rejected the same way.
func (suite *ResourceSharingAuthzTestSuite) TestWriteTimeDefense_UpdateRoleRejectsPermissionNotVisibleToOU() {
	roleID, err := testutils.CreateRole(testutils.Role{
		Name: "res-sharing-authz-write-time-update",
		OUID: suite.shareeOUID,
		Permissions: []testutils.ResourcePermissions{
			{ResourceServerID: suite.bookingsRSID, Permissions: []string{"bookings:view"}},
		},
	})
	suite.Require().NoError(err, "the initial role, naming only the still-shared permission, must be created")
	defer func() {
		if delErr := testutils.DeleteRole(roleID); delErr != nil {
			suite.T().Logf("Failed to delete temporary role %s: %v", roleID, delErr)
		}
	}()

	err = testutils.UpdateRole(roleID, testutils.Role{
		Name: "res-sharing-authz-write-time-update",
		OUID: suite.shareeOUID,
		Permissions: []testutils.ResourcePermissions{
			{ResourceServerID: suite.bookingsRSID, Permissions: []string{"bookings:view", "bookings:create"}},
		},
	})
	suite.Require().Error(err, "updating a role to add an unshared permission must fail")
	suite.Contains(err.Error(), "ROL-1025")
}

// TestUnshare_StripsPermissionFromExistingRole proves that unsharing an action doesn't just hide
// its permission at read time (behavior 6, above): the permission is actually removed from every
// role owned by the OU that lost access, so the role's own stored definition never claims more
// than it can use.
//
// Uses a fresh resource and action under the already-shared bookingsRS (rather than the shared
// suite fixture's own bookings/view/create) so this test's unshare doesn't disturb the sharing
// state the other tests in this suite depend on. Creating the action under an already-shared
// resource server exercises auto-inherit on creation (§5.2) as a side effect: no separate share
// call is needed for the new action to become visible to shareeOU.
func (suite *ResourceSharingAuthzTestSuite) TestUnshare_StripsPermissionFromExistingRole() {
	// resourceID/actionID need no separate cleanup: they are torn down along with bookingsRSID
	// itself in TearDownSuite (testutils.DeleteResourceServerWithChildren).
	resourceID, err := createResource(suite.bookingsRSID, CreateResourceRequest{Name: "Invoices", Handle: "invoices"})
	suite.Require().NoError(err, "Failed to create invoices resource")

	actionID, err := createActionAtResource(suite.bookingsRSID, resourceID, CreateActionRequest{Name: "Send", Handle: "send"})
	suite.Require().NoError(err, "Failed to create send action")

	grants, err := testutils.ListActionGrants(suite.bookingsRSID, resourceID, actionID)
	suite.Require().NoError(err)
	suite.Require().Len(grants, 1, "the new action must auto-inherit bookingsRS's cascade share to shareeOU")

	roleID, err := testutils.CreateRole(testutils.Role{
		Name: "res-sharing-authz-unshare-strips-permission",
		OUID: suite.shareeOUID,
		Permissions: []testutils.ResourcePermissions{
			{ResourceServerID: suite.bookingsRSID, Permissions: []string{"bookings:view", "invoices:send"}},
		},
	})
	suite.Require().NoError(err, "the role, naming both a stable and a soon-to-be-unshared permission, must be created")
	defer func() {
		if delErr := testutils.DeleteRole(roleID); delErr != nil {
			suite.T().Logf("Failed to delete temporary role %s: %v", roleID, delErr)
		}
	}()

	before, err := testutils.GetRole(roleID)
	suite.Require().NoError(err)
	suite.Require().Len(before.Permissions, 1)
	suite.ElementsMatch([]string{"bookings:view", "invoices:send"}, before.Permissions[0].Permissions,
		"both permissions must be stored before the unshare")

	suite.Require().NoError(testutils.UnshareActionGrant(suite.bookingsRSID, resourceID, actionID, grants[0].ID))

	after, err := testutils.GetRole(roleID)
	suite.Require().NoError(err)
	suite.Require().Len(after.Permissions, 1)
	suite.ElementsMatch([]string{"bookings:view"}, after.Permissions[0].Permissions,
		"invoices:send must be stripped from the role's own stored permissions after being unshared, "+
			"not merely hidden at read time")
}

// TestReshareDoesNotResurrectStrippedPermission pins the interaction between §5.4's cleanup and
// re-sharing, which is easy to get wrong when writing a demo flow: because unsharing an action
// physically removes the permission from every role in the losing OU, later re-sharing that action
// does NOT restore it. The role's own stored permission list no longer names it, so a fresh token
// still lacks it until the role is explicitly updated to claim it again.
//
// This is deliberate. Re-adding the permission is a grant decision the role's owner must make
// again, and §4.3's write-time check re-validates visibility at that moment, so a permission never
// silently reappears on a role just because an unrelated administrator re-shared the action.
func (suite *ResourceSharingAuthzTestSuite) TestReshareDoesNotResurrectStrippedPermission() {
	resourceID, err := createResource(suite.bookingsRSID,
		CreateResourceRequest{Name: "Payouts", Handle: "payouts"})
	suite.Require().NoError(err)
	actionID, err := createActionAtResource(suite.bookingsRSID, resourceID,
		CreateActionRequest{Name: "Settle", Handle: "settle"})
	suite.Require().NoError(err)

	grants, err := testutils.ListActionGrants(suite.bookingsRSID, resourceID, actionID)
	suite.Require().NoError(err)
	suite.Require().Len(grants, 1, "the new action auto-inherits the resource server's cascade share")

	roleID, err := testutils.CreateRole(testutils.Role{
		Name: "res-sharing-authz-reshare-role",
		OUID: suite.shareeOUID,
		Permissions: []testutils.ResourcePermissions{
			{ResourceServerID: suite.bookingsRSID, Permissions: []string{"bookings:view", "payouts:settle"}},
		},
	})
	suite.Require().NoError(err)
	defer func() {
		if delErr := testutils.DeleteRole(roleID); delErr != nil {
			suite.T().Logf("delete role %s: %v", roleID, delErr)
		}
	}()

	// Unshare: §5.4 strips payouts:settle from the role.
	suite.Require().NoError(
		testutils.UnshareActionGrant(suite.bookingsRSID, resourceID, actionID, grants[0].ID))

	stripped, err := testutils.GetRole(roleID)
	suite.Require().NoError(err)
	suite.Require().Len(stripped.Permissions, 1)
	suite.ElementsMatch([]string{"bookings:view"}, stripped.Permissions[0].Permissions,
		"the unshare must have stripped payouts:settle")

	// Re-share the very same action.
	reshared, err := testutils.ShareAction(suite.bookingsRSID, resourceID, actionID,
		map[string]interface{}{"rootOuIds": []string{suite.shareeOUID}})
	suite.Require().NoError(err)
	suite.Require().NotEmpty(reshared)

	// The role still does not claim it: re-sharing restores visibility, never the grant itself.
	afterReshare, err := testutils.GetRole(roleID)
	suite.Require().NoError(err)
	suite.Require().Len(afterReshare.Permissions, 1)
	suite.ElementsMatch([]string{"bookings:view"}, afterReshare.Permissions[0].Permissions,
		"re-sharing must not silently resurrect a permission the unshare removed")

	// Only an explicit role update re-adds it, and it now succeeds because the action is visible
	// again (the same update would have been rejected with ROL-1025 while it was unshared).
	suite.Require().NoError(testutils.UpdateRole(roleID, testutils.Role{
		Name: "res-sharing-authz-reshare-role",
		OUID: suite.shareeOUID,
		Permissions: []testutils.ResourcePermissions{
			{ResourceServerID: suite.bookingsRSID, Permissions: []string{"bookings:view", "payouts:settle"}},
		},
	}))

	restored, err := testutils.GetRole(roleID)
	suite.Require().NoError(err)
	suite.Require().Len(restored.Permissions, 1)
	suite.ElementsMatch([]string{"bookings:view", "payouts:settle"}, restored.Permissions[0].Permissions,
		"an explicit update re-adds the permission once the action is visible again")
}

// TestCascadeUnshareStripsEveryDescendantPermission proves the cascade case of §5.4: revoking the
// resource-server-level grant revokes each descendant's own grant individually (§5.3), so each one
// fires the same role-permission cleanup. Every permission the role named under that server is
// removed, not just the one node the caller named. This is what the Postman collection's cascade
// unshare folder asserts, verified here against a real server.
func (suite *ResourceSharingAuthzTestSuite) TestCascadeUnshareStripsEveryDescendantPermission() {
	// A self-contained resource server so revoking its top-level grant cannot disturb the shared
	// suite fixture the other tests depend on.
	rsID, err := createResourceServer(CreateResourceServerRequest{
		Name:       "Resource Sharing Authz Cascade RS",
		OUID:       suite.ownerOUID,
		Identifier: "https://res-sharing-authz.example.com/cascade",
	})
	suite.Require().NoError(err)
	defer func() {
		if delErr := testutils.DeleteResourceServerWithChildren(rsID); delErr != nil {
			suite.T().Logf("delete cascade resource server: %v", delErr)
		}
	}()

	resourceID, err := createResource(rsID, CreateResourceRequest{Name: "Orders", Handle: "orders"})
	suite.Require().NoError(err)
	for _, handle := range []string{"read", "write"} {
		_, err = createActionAtResource(rsID, resourceID,
			CreateActionRequest{Name: handle, Handle: handle})
		suite.Require().NoError(err)
	}

	grants, err := testutils.ShareResourceServer(rsID, map[string]interface{}{
		"rootOuIds": []string{suite.shareeOUID},
	})
	suite.Require().NoError(err)
	suite.Require().Len(grants, 4, "server + orders + read + write")

	var serverGrantID string
	for _, g := range grants {
		if g.NodeType == "resource_server" && g.NodeID == rsID {
			serverGrantID = g.ID
		}
	}
	suite.Require().NotEmpty(serverGrantID)

	roleID, err := testutils.CreateRole(testutils.Role{
		Name: "res-sharing-authz-cascade-role",
		OUID: suite.shareeOUID,
		Permissions: []testutils.ResourcePermissions{
			{ResourceServerID: rsID, Permissions: []string{"orders", "orders:read", "orders:write"}},
		},
	})
	suite.Require().NoError(err)
	defer func() {
		if delErr := testutils.DeleteRole(roleID); delErr != nil {
			suite.T().Logf("delete role %s: %v", roleID, delErr)
		}
	}()

	before, err := testutils.GetRole(roleID)
	suite.Require().NoError(err)
	suite.Require().Len(before.Permissions, 1)
	suite.Require().Len(before.Permissions[0].Permissions, 3)

	// One revoke, at the top of the tree.
	suite.Require().NoError(testutils.UnshareResourceServerGrant(rsID, serverGrantID))

	after, err := testutils.GetRole(roleID)
	suite.Require().NoError(err)
	if len(after.Permissions) > 0 {
		suite.Empty(after.Permissions[0].Permissions,
			"every permission under the unshared resource server must be stripped, not just one")
	}
}
