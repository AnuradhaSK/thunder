// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/thunder-id/thunderid/tests/integration/testutils"
)

// ResourceScopeAuthzTestSuite pins the authorization boundary of the Resource Management API, which
// now has a granular view/manage scope pair (system:resource-servers /
// system:resource-servers:view) instead of falling through to the bare root "system" permission,
// plus per-caller organization unit confinement on top. Both tiers are exercised against real
// client_credentials tokens, so the middleware, the service-layer OU checks, and the sharing
// framework's ownership invariant are all covered end to end.
//
// Two layers answer a refusal here, and the tests assert on the specific error code rather than the
// status alone so the layers stay distinguishable:
//
//	AUTH-4030 — the security middleware: the caller's token lacks the scope the path requires.
//	RES-1024  — internal/resource: the caller holds the scope but targeted an organization unit
//	            outside its own (and, for reads, one that was never shared to it).
//	SHR-1007  — the sharing framework: the caller may not modify core config it does not own.
//
// Fixture topology:
//
//	ownerOU  owns targetRS, the resource server every negative case tries and fails to touch.
//	shareeOU owns scopeRS (a resource server reproducing the system:resource-servers permission
//	         tree, since the product ships only the root "system" scope) and hosts three M2M apps:
//	         a view-scoped one, a manage-scoped one, and one holding an unrelated scope entirely.
//	         Every app's token carries shareeOU as its ouId claim, so shareeOU is the "own OU" all
//	         three are confined to.
type ResourceScopeAuthzTestSuite struct {
	suite.Suite

	ownerOUID  string
	shareeOUID string

	targetRSID       string
	targetResourceID string
	scopeRSID        string

	viewAppID      string
	manageAppID    string
	unrelatedAppID string
	viewRoleID     string
	manageRoleID   string
	unrelatedRole  string

	// Resource servers created by the positive-path tests, torn down in TearDownSuite in case an
	// assertion failed before the test's own cleanup ran.
	createdRSIDs []string
}

const (
	scopeAuthzOwnerOUHandle  = "res-scope-authz-owner-ou"
	scopeAuthzShareeOUHandle = "res-scope-authz-sharee-ou"

	scopeAuthzTargetRSIdentifier = "https://res-scope-authz.example.com/target"
	scopeAuthzScopeRSIdentifier  = "https://res-scope-authz.example.com/scopes"

	scopeAuthzViewClientID   = "res_scope_authz_view_client"
	scopeAuthzViewSecret     = "res_scope_authz_view_secret"
	scopeAuthzManageClientID = "res_scope_authz_manage_client"
	scopeAuthzManageSecret   = "res_scope_authz_manage_secret"
	scopeAuthzOtherClientID  = "res_scope_authz_other_client"
	scopeAuthzOtherSecret    = "res_scope_authz_other_secret"

	// The two scopes under test, and one deliberately unrelated scope.
	scopeResourceServers     = "system:resource-servers"
	scopeResourceServersView = "system:resource-servers:view"
	scopeUnrelated           = "system:group:view"

	// errCodeInsufficientPermissions is returned by the security middleware when the caller's token
	// does not carry the permission the requested path requires.
	scopeAuthzErrInsufficient = "AUTH-4030"
	// scopeAuthzErrOutsideOwnOU is internal/resource's own confinement error (RES-1024).
	scopeAuthzErrOutsideOwnOU = "RES-1024"
	// scopeAuthzErrOwnerOnly is the sharing framework's core-config ownership invariant (SHR-1007).
	scopeAuthzErrOwnerOnly = "SHR-1007"
)

func TestResourceScopeAuthzTestSuite(t *testing.T) {
	suite.Run(t, new(ResourceScopeAuthzTestSuite))
}

func (ts *ResourceScopeAuthzTestSuite) SetupSuite() {
	ownerID, err := testutils.CreateOrganizationUnit(testutils.OrganizationUnit{
		Handle:      scopeAuthzOwnerOUHandle,
		Name:        "Resource Scope Authz Owner OU",
		Description: "Owns the resource server every negative case fails to touch",
	})
	ts.Require().NoError(err, "create owner OU")
	ts.ownerOUID = ownerID

	shareeID, err := testutils.CreateOrganizationUnit(testutils.OrganizationUnit{
		Handle:      scopeAuthzShareeOUHandle,
		Name:        "Resource Scope Authz Sharee OU",
		Description: "Hosts the scoped administrator apps; the OU they are all confined to",
	})
	ts.Require().NoError(err, "create sharee OU")
	ts.shareeOUID = shareeID

	// The resource server the negative cases target, owned by an OU none of the scoped callers
	// belong to, and never shared to shareeOU.
	targetRSID, err := createResourceServer(CreateResourceServerRequest{
		Name:       "Resource Scope Authz Target RS",
		OUID:       ts.ownerOUID,
		Identifier: scopeAuthzTargetRSIdentifier,
	})
	ts.Require().NoError(err, "create target resource server")
	ts.targetRSID = targetRSID

	targetResourceID, err := createResource(targetRSID, CreateResourceRequest{Name: "Books", Handle: "books"})
	ts.Require().NoError(err, "create target resource")
	ts.targetResourceID = targetResourceID

	// The product ships only the root "system" scope, so the fine-grained permissions the scoped
	// callers hold are reproduced on a resource server of the suite's own, exactly as
	// tests/integration/role/role_authz_test.go does. "resource-servers" as a child of "system"
	// yields system:resource-servers plus its own system:resource-servers:view action.
	scopeRSID, err := testutils.CreateSystemScopedResourceServer(
		ts.shareeOUID, "Resource Scope Authz Scope RS", scopeAuthzScopeRSIdentifier,
		"resource-servers", "group")
	ts.Require().NoError(err, "create scope resource server")
	ts.scopeRSID = scopeRSID

	ts.viewAppID, ts.viewRoleID = ts.provisionScopedApp(
		"view", scopeAuthzViewClientID, scopeAuthzViewSecret, scopeResourceServersView)
	ts.manageAppID, ts.manageRoleID = ts.provisionScopedApp(
		"manage", scopeAuthzManageClientID, scopeAuthzManageSecret, scopeResourceServers)
	ts.unrelatedAppID, ts.unrelatedRole = ts.provisionScopedApp(
		"other", scopeAuthzOtherClientID, scopeAuthzOtherSecret, scopeUnrelated)
}

func (ts *ResourceScopeAuthzTestSuite) TearDownSuite() {
	for _, id := range ts.createdRSIDs {
		_ = testutils.DeleteResourceServerWithChildren(id)
	}
	for _, id := range []string{ts.viewRoleID, ts.manageRoleID, ts.unrelatedRole} {
		if id != "" {
			if err := testutils.DeleteRole(id); err != nil {
				ts.T().Logf("delete role %s: %v", id, err)
			}
		}
	}
	for _, id := range []string{ts.viewAppID, ts.manageAppID, ts.unrelatedAppID} {
		if id != "" {
			if err := testutils.DeleteApplication(id); err != nil {
				ts.T().Logf("delete application %s: %v", id, err)
			}
		}
	}
	if ts.scopeRSID != "" {
		if err := testutils.DeleteResourceServerWithChildren(ts.scopeRSID); err != nil {
			ts.T().Logf("delete scope resource server: %v", err)
		}
	}
	if ts.targetRSID != "" {
		if err := testutils.DeleteResourceServerWithChildren(ts.targetRSID); err != nil {
			ts.T().Logf("delete target resource server: %v", err)
		}
	}
	for _, id := range []string{ts.shareeOUID, ts.ownerOUID} {
		if id != "" {
			if err := testutils.DeleteOrganizationUnit(id); err != nil {
				ts.T().Logf("delete OU %s: %v", id, err)
			}
		}
	}
}

// provisionScopedApp creates an M2M application in shareeOU whose client_credentials token carries
// exactly one permission plus shareeOU as its ouId claim, and a role conferring that permission.
// The ouId claim requires an explicit token.accessToken.clientConfig.attributes opt-in, without
// which the token has no OU at all and internal/resource's confinement would reject every call
// (correctly, but for the wrong reason, which would make these tests prove nothing).
func (ts *ResourceScopeAuthzTestSuite) provisionScopedApp(
	label, clientID, clientSecret, permission string,
) (appID, roleID string) {
	ts.T().Helper()

	app := map[string]interface{}{
		"name":                      "Resource Scope Authz App (" + label + ")",
		"description":               "Scoped administrator app holding only " + permission,
		"ouId":                      ts.shareeOUID,
		"type":                      "m2m",
		"isRegistrationFlowEnabled": false,
		"inboundAuthConfig": []map[string]interface{}{
			{
				"type": "oauth2",
				"config": map[string]interface{}{
					"clientId":                clientID,
					"clientSecret":            clientSecret,
					"grantTypes":              []string{"client_credentials"},
					"tokenEndpointAuthMethod": "client_secret_basic",
					"token": map[string]interface{}{
						"accessToken": map[string]interface{}{
							"clientConfig": map[string]interface{}{
								"attributes": []string{"ouId"},
							},
						},
					},
				},
			},
		},
	}

	payload, err := json.Marshal(app)
	ts.Require().NoError(err)
	req, err := http.NewRequest("POST", testServerURL+"/applications", bytes.NewReader(payload))
	ts.Require().NoError(err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := testutils.GetHTTPClient().Do(req)
	ts.Require().NoError(err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	ts.Require().Equal(http.StatusCreated, resp.StatusCode,
		"create %s app: %s", label, string(body))

	var created map[string]interface{}
	ts.Require().NoError(json.Unmarshal(body, &created))
	appID, _ = created["id"].(string)
	ts.Require().NotEmpty(appID)

	roleID, err = testutils.CreateRole(testutils.Role{
		Name: "res-scope-authz-" + label + "-role",
		OUID: ts.shareeOUID,
		Permissions: []testutils.ResourcePermissions{
			{ResourceServerID: ts.scopeRSID, Permissions: []string{permission}},
		},
		Assignments: []testutils.Assignment{{ID: appID, Type: "app"}},
	})
	ts.Require().NoError(err, "create %s role", label)

	return appID, roleID
}

// tokenFor mints a client_credentials token for the given client, bound to the scope resource
// server so the requested permission survives downscoping, and asserts it actually came back with
// that permission in its scope (a token silently downscoped to nothing would make every negative
// assertion below pass for the wrong reason).
func (ts *ResourceScopeAuthzTestSuite) tokenFor(clientID, clientSecret, permission string) string {
	ts.T().Helper()

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", permission)
	form.Set("resource", scopeAuthzScopeRSIdentifier)

	req, err := http.NewRequest("POST", testServerURL+"/oauth2/token", strings.NewReader(form.Encode()))
	ts.Require().NoError(err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := testutils.GetHTTPClient().Do(req)
	ts.Require().NoError(err)
	defer resp.Body.Close()

	var body map[string]interface{}
	ts.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))
	ts.Require().Equal(http.StatusOK, resp.StatusCode, "token request failed: %v", body)

	token, _ := body["access_token"].(string)
	ts.Require().NotEmpty(token, "token response carried no access_token: %v", body)
	scopeStr, _ := body["scope"].(string)
	ts.Require().Contains(strings.Fields(scopeStr), permission,
		"token must carry %q; RBAC resolution dropped it: %v", permission, body)

	return token
}

// call issues an authenticated request and returns the status plus the response body's error code
// (empty when the body carries no code, e.g. on success).
func (ts *ResourceScopeAuthzTestSuite) call(
	token, method, path string, payload interface{},
) (int, string) {
	ts.T().Helper()

	var reader io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		ts.Require().NoError(err)
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, testServerURL+path, reader)
	ts.Require().NoError(err)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := testutils.GetHTTPClientWithToken(token).Do(req)
	ts.Require().NoError(err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var errResp struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(body, &errResp)
	return resp.StatusCode, errResp.Code
}

// ---------------------------------------------------------------------------
// Scope tier: view cannot write, and an unrelated scope cannot reach the API at all
// ---------------------------------------------------------------------------

// TestViewScopeCannotWrite proves the view/manage split: system:resource-servers:view satisfies
// every GET route but no POST/PUT/DELETE route, so the middleware refuses each write before it
// reaches a handler. Each case targets the caller's OWN organization unit, so a refusal can only be
// the scope tier talking, never the OU tier.
func (ts *ResourceScopeAuthzTestSuite) TestViewScopeCannotWrite() {
	token := ts.tokenFor(scopeAuthzViewClientID, scopeAuthzViewSecret, scopeResourceServersView)

	testCases := []struct {
		name    string
		method  string
		path    string
		payload interface{}
	}{
		{
			name:   "CreateResourceServer",
			method: http.MethodPost,
			path:   "/resource-servers",
			payload: map[string]interface{}{
				"name":       "Resource Scope Authz Denied RS",
				"ouId":       ts.shareeOUID,
				"identifier": "https://res-scope-authz.example.com/denied",
			},
		},
		{
			name:    "UpdateResourceServer",
			method:  http.MethodPut,
			path:    "/resource-servers/" + ts.scopeRSID,
			payload: map[string]interface{}{"name": "Renamed", "ouId": ts.shareeOUID},
		},
		{
			name:   "DeleteResourceServer",
			method: http.MethodDelete,
			path:   "/resource-servers/" + ts.scopeRSID,
		},
		{
			name:    "CreateResource",
			method:  http.MethodPost,
			path:    "/resource-servers/" + ts.scopeRSID + "/resources",
			payload: map[string]interface{}{"name": "Denied", "handle": "denied"},
		},
		{
			name:    "CreateAction",
			method:  http.MethodPost,
			path:    "/resource-servers/" + ts.scopeRSID + "/actions",
			payload: map[string]interface{}{"name": "Denied", "handle": "denied"},
		},
		{
			// Sharing is a manage operation: read-only access must not let a caller redistribute
			// what it can see.
			name:    "ShareResourceServer",
			method:  http.MethodPost,
			path:    "/resource-servers/" + ts.scopeRSID + "/grants",
			payload: map[string]interface{}{"allChildren": true},
		},
		{
			name:   "UnshareResourceServerGrant",
			method: http.MethodDelete,
			path:   "/resource-servers/" + ts.scopeRSID + "/grants/some-grant-id",
		},
	}

	for _, tc := range testCases {
		ts.Run(tc.name, func() {
			status, code := ts.call(token, tc.method, tc.path, tc.payload)
			ts.Equal(http.StatusForbidden, status)
			ts.Equal(scopeAuthzErrInsufficient, code,
				"the view scope must be refused by the middleware, not by a handler")
		})
	}
}

// TestUnrelatedScopeCannotReachAPI proves a caller holding neither resource-server scope is refused
// on the Resource Management API outright, read included.
func (ts *ResourceScopeAuthzTestSuite) TestUnrelatedScopeCannotReachAPI() {
	token := ts.tokenFor(scopeAuthzOtherClientID, scopeAuthzOtherSecret, scopeUnrelated)

	testCases := []struct {
		name   string
		method string
		path   string
	}{
		{name: "ListResourceServers", method: http.MethodGet, path: "/resource-servers"},
		{name: "GetResourceServer", method: http.MethodGet, path: "/resource-servers/" + ts.scopeRSID},
		{
			name:   "ListGrants",
			method: http.MethodGet,
			path:   "/resource-servers/" + ts.scopeRSID + "/grants",
		},
	}

	for _, tc := range testCases {
		ts.Run(tc.name, func() {
			status, code := ts.call(token, tc.method, tc.path, nil)
			ts.Equal(http.StatusForbidden, status)
			ts.Equal(scopeAuthzErrInsufficient, code)
		})
	}
}

// TestViewScopeCanRead is the positive contrast to TestViewScopeCannotWrite: the same token that
// cannot write must still satisfy the read routes for a resource server in its own OU. Without
// this, the negative cases above would also pass if the scope were simply broken.
func (ts *ResourceScopeAuthzTestSuite) TestViewScopeCanRead() {
	token := ts.tokenFor(scopeAuthzViewClientID, scopeAuthzViewSecret, scopeResourceServersView)

	status, code := ts.call(token, http.MethodGet, "/resource-servers/"+ts.scopeRSID, nil)
	ts.Equal(http.StatusOK, status, "unexpected error code %q", code)

	status, code = ts.call(token, http.MethodGet, "/resource-servers/"+ts.scopeRSID+"/grants", nil)
	ts.Equal(http.StatusOK, status, "unexpected error code %q", code)
}

// ---------------------------------------------------------------------------
// OU tier: the manage scope does not reach outside the caller's own OU
// ---------------------------------------------------------------------------

// TestManageScopeCannotCreateOutsideOwnOU proves the create paths' requireOwnOUScope: a caller
// holding the full manage scope still cannot create a resource server in an OU it does not own, nor
// add resources/actions under another OU's resource server. This is the OU tier, so the refusal
// carries RES-1024 rather than the middleware's AUTH-4030.
func (ts *ResourceScopeAuthzTestSuite) TestManageScopeCannotCreateOutsideOwnOU() {
	token := ts.tokenFor(scopeAuthzManageClientID, scopeAuthzManageSecret, scopeResourceServers)

	testCases := []struct {
		name    string
		method  string
		path    string
		payload interface{}
	}{
		{
			name:   "CreateResourceServerInForeignOU",
			method: http.MethodPost,
			path:   "/resource-servers",
			payload: map[string]interface{}{
				"name":       "Resource Scope Authz Foreign RS",
				"ouId":       ts.ownerOUID,
				"identifier": "https://res-scope-authz.example.com/foreign",
			},
		},
		{
			name:    "CreateResourceUnderForeignOUsServer",
			method:  http.MethodPost,
			path:    "/resource-servers/" + ts.targetRSID + "/resources",
			payload: map[string]interface{}{"name": "Sneaky", "handle": "sneaky"},
		},
		{
			name:    "CreateActionUnderForeignOUsServer",
			method:  http.MethodPost,
			path:    "/resource-servers/" + ts.targetRSID + "/actions",
			payload: map[string]interface{}{"name": "Sneaky", "handle": "sneaky"},
		},
	}

	for _, tc := range testCases {
		ts.Run(tc.name, func() {
			status, code := ts.call(token, tc.method, tc.path, tc.payload)
			ts.Equal(http.StatusForbidden, status)
			ts.Equal(scopeAuthzErrOutsideOwnOU, code,
				"the manage scope confines the caller to its own organization unit")
		})
	}
}

// TestManageScopeCannotModifyForeignOUsServer proves update and delete defer to the sharing
// framework's ownership invariant instead of requireOwnOUScope, so they surface SHR-1007. The
// distinction matters: these protect an already-existing resource's core config, which is never
// editable by a non-owner even when it is visible through a grant.
func (ts *ResourceScopeAuthzTestSuite) TestManageScopeCannotModifyForeignOUsServer() {
	token := ts.tokenFor(scopeAuthzManageClientID, scopeAuthzManageSecret, scopeResourceServers)

	testCases := []struct {
		name    string
		method  string
		path    string
		payload interface{}
	}{
		{
			name:    "UpdateForeignOUsResourceServer",
			method:  http.MethodPut,
			path:    "/resource-servers/" + ts.targetRSID,
			payload: map[string]interface{}{"name": "Hijacked", "ouId": ts.ownerOUID},
		},
		{
			name:   "DeleteForeignOUsResourceServer",
			method: http.MethodDelete,
			path:   "/resource-servers/" + ts.targetRSID,
		},
		{
			name:    "UpdateForeignOUsResource",
			method:  http.MethodPut,
			path:    "/resource-servers/" + ts.targetRSID + "/resources/" + ts.targetResourceID,
			payload: map[string]interface{}{"name": "Hijacked"},
		},
		{
			name:   "DeleteForeignOUsResource",
			method: http.MethodDelete,
			path:   "/resource-servers/" + ts.targetRSID + "/resources/" + ts.targetResourceID,
		},
	}

	for _, tc := range testCases {
		ts.Run(tc.name, func() {
			status, code := ts.call(token, tc.method, tc.path, tc.payload)
			ts.Equal(http.StatusForbidden, status)
			ts.Equal(scopeAuthzErrOwnerOnly, code,
				"core config of a resource the caller does not own is never editable")
		})
	}
}

// TestManageScopeCannotReadOrShareForeignOUsServer proves RequireVisibility on the read and
// share-grant paths: a resource server neither owned by nor shared to the caller's OU is invisible,
// and so cannot be read or redistributed.
func (ts *ResourceScopeAuthzTestSuite) TestManageScopeCannotReadOrShareForeignOUsServer() {
	token := ts.tokenFor(scopeAuthzManageClientID, scopeAuthzManageSecret, scopeResourceServers)

	testCases := []struct {
		name    string
		method  string
		path    string
		payload interface{}
	}{
		{
			name:   "GetForeignOUsResourceServer",
			method: http.MethodGet,
			path:   "/resource-servers/" + ts.targetRSID,
		},
		{
			name:   "GetForeignOUsResource",
			method: http.MethodGet,
			path:   "/resource-servers/" + ts.targetRSID + "/resources/" + ts.targetResourceID,
		},
		{
			name:   "ListForeignOUsGrants",
			method: http.MethodGet,
			path:   "/resource-servers/" + ts.targetRSID + "/grants",
		},
		{
			name:    "ShareForeignOUsResourceServer",
			method:  http.MethodPost,
			path:    "/resource-servers/" + ts.targetRSID + "/grants",
			payload: map[string]interface{}{"allChildren": true},
		},
	}

	for _, tc := range testCases {
		ts.Run(tc.name, func() {
			status, code := ts.call(token, tc.method, tc.path, tc.payload)
			ts.Equal(http.StatusForbidden, status)
			ts.Equal(scopeAuthzErrOutsideOwnOU, code,
				"a resource server neither owned by nor shared to the caller is invisible")
		})
	}
}

// TestManageScopeCanManageOwnOU is the positive contrast to every OU-tier negative above: the same
// manage token that cannot touch ownerOU's resource server can create, read, share, update, and
// delete one in its own OU. Run as one sequence so the created resource server's whole lifecycle is
// covered by a caller that never holds the root permission.
func (ts *ResourceScopeAuthzTestSuite) TestManageScopeCanManageOwnOU() {
	token := ts.tokenFor(scopeAuthzManageClientID, scopeAuthzManageSecret, scopeResourceServers)

	// Create, in the caller's own OU.
	payload, err := json.Marshal(map[string]interface{}{
		"name":       "Resource Scope Authz Own RS",
		"ouId":       ts.shareeOUID,
		"identifier": "https://res-scope-authz.example.com/own",
	})
	ts.Require().NoError(err)
	req, err := http.NewRequest("POST", testServerURL+"/resource-servers", bytes.NewReader(payload))
	ts.Require().NoError(err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := testutils.GetHTTPClientWithToken(token).Do(req)
	ts.Require().NoError(err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	ts.Require().Equal(http.StatusCreated, resp.StatusCode, "create in own OU: %s", string(body))

	var created map[string]interface{}
	ts.Require().NoError(json.Unmarshal(body, &created))
	ownRSID, _ := created["id"].(string)
	ts.Require().NotEmpty(ownRSID)
	ts.createdRSIDs = append(ts.createdRSIDs, ownRSID)

	// Read it back.
	status, code := ts.call(token, http.MethodGet, "/resource-servers/"+ownRSID, nil)
	ts.Equal(http.StatusOK, status, "read own OU's server: %q", code)

	// Add a resource, then share the server to ownerOU's tree (proving manage really does allow
	// distribution, not merely local edits).
	status, code = ts.call(token, http.MethodPost, "/resource-servers/"+ownRSID+"/resources",
		map[string]interface{}{"name": "Invoices", "handle": "invoices"})
	ts.Equal(http.StatusCreated, status, "create resource in own OU: %q", code)

	status, code = ts.call(token, http.MethodPost, "/resource-servers/"+ownRSID+"/grants",
		map[string]interface{}{"rootOuIds": []string{ts.ownerOUID}})
	ts.Equal(http.StatusCreated, status, "share own OU's server: %q", code)

	// Update and delete it. Deleting the server itself is refused while its resource still exists
	// (RES-1006), so the resource goes first.
	status, code = ts.call(token, http.MethodPut, "/resource-servers/"+ownRSID,
		map[string]interface{}{"name": "Resource Scope Authz Own RS Renamed", "ouId": ts.shareeOUID})
	ts.Equal(http.StatusOK, status, "update own OU's server: %q", code)

	ts.Require().NoError(testutils.DeleteResourceServerWithChildren(ownRSID),
		"tear down the resource server this test created")
	ts.createdRSIDs = ts.createdRSIDs[:len(ts.createdRSIDs)-1]
}

// TestManageScopeCanReadSharedResourceServer proves RequireVisibility's share fallback: once
// ownerOU shares its resource server to shareeOU, the manage-scoped caller can read it even though
// it still does not own it, while core-config writes stay refused with SHR-1007.
func (ts *ResourceScopeAuthzTestSuite) TestManageScopeCanReadSharedResourceServer() {
	grants, err := testutils.ShareResourceServer(ts.targetRSID, map[string]interface{}{
		"rootOuIds": []string{ts.shareeOUID},
	})
	ts.Require().NoError(err, "share the target resource server to shareeOU")
	ts.Require().NotEmpty(grants)

	var serverGrantID string
	for _, g := range grants {
		if g.NodeType == "resource_server" && g.NodeID == ts.targetRSID {
			serverGrantID = g.ID
		}
	}
	ts.Require().NotEmpty(serverGrantID, "find the resource-server-level grant")
	defer func() {
		if err := testutils.UnshareResourceServerGrant(ts.targetRSID, serverGrantID); err != nil {
			ts.T().Logf("unshare target resource server: %v", err)
		}
	}()

	token := ts.tokenFor(scopeAuthzManageClientID, scopeAuthzManageSecret, scopeResourceServers)

	status, code := ts.call(token, http.MethodGet, "/resource-servers/"+ts.targetRSID, nil)
	ts.Equal(http.StatusOK, status, "a shared resource server must be readable: %q", code)

	status, code = ts.call(token, http.MethodGet,
		fmt.Sprintf("/resource-servers/%s/resources/%s", ts.targetRSID, ts.targetResourceID), nil)
	ts.Equal(http.StatusOK, status, "a shared resource must be readable: %q", code)

	// Visibility is not ownership: core config stays owner-only.
	status, code = ts.call(token, http.MethodPut, "/resource-servers/"+ts.targetRSID,
		map[string]interface{}{"name": "Hijacked", "ouId": ts.ownerOUID})
	ts.Equal(http.StatusForbidden, status)
	ts.Equal(scopeAuthzErrOwnerOnly, code,
		"share visibility must never confer the right to edit core config")
}

// TestListIsConfinedToOwnOU proves the list endpoint is OU-filtered for a non-root caller, closing
// the gap that a scoped administrator could otherwise enumerate every resource server in the
// deployment. ownerOU's targetRS is never shared to shareeOU, so it must not appear; the caller's
// own scopeRS must.
func (ts *ResourceScopeAuthzTestSuite) TestListIsConfinedToOwnOU() {
	token := ts.tokenFor(scopeAuthzViewClientID, scopeAuthzViewSecret, scopeResourceServersView)

	req, err := http.NewRequest(http.MethodGet, testServerURL+"/resource-servers?limit=100", nil)
	ts.Require().NoError(err)
	resp, err := testutils.GetHTTPClientWithToken(token).Do(req)
	ts.Require().NoError(err)
	defer resp.Body.Close()
	ts.Require().Equal(http.StatusOK, resp.StatusCode)

	var listed struct {
		TotalResults    int `json:"totalResults"`
		ResourceServers []struct {
			ID string `json:"id"`
		} `json:"resourceServers"`
	}
	ts.Require().NoError(json.NewDecoder(resp.Body).Decode(&listed))

	ids := make([]string, 0, len(listed.ResourceServers))
	for _, rs := range listed.ResourceServers {
		ids = append(ids, rs.ID)
	}
	ts.Contains(ids, ts.scopeRSID, "the caller's own resource server must be listed")
	ts.NotContains(ids, ts.targetRSID,
		"another OU's resource server must never appear in a scoped caller's listing")
	// Confinement must not hide the System resource server: it is shared deployment-wide at
	// bootstrap precisely so every organization unit can see the permissions that gate the
	// management APIs. A scoped administrator that could not see it could not manage its own
	// roles' system permissions at all.
	ts.Contains(ids, systemResourceServerID,
		"the System resource server is shared to every OU and must appear in a scoped listing")
	ts.Equal(len(listed.ResourceServers), listed.TotalResults,
		"totalResults must reflect the filtered set, not the deployment-wide count")
}

// systemResourceServerID is the bootstrap System resource server, whose resources define the
// permissions that gate the management APIs themselves (see
// backend/cmd/server/bootstrap/01-default-resources.yaml).
const systemResourceServerID = "01900000-0000-7000-8000-000000000020"

// TestSystemResourceServerIsSharedDeploymentWide proves the bootstrap `grants: [allOus: true]`
// on the System resource server actually took effect, which is what makes the management
// permissions usable outside the default organization unit at all.
//
// Without it, a role in any other organization unit naming a system permission is rejected at
// write time (ROL-1025) and its permissions are dropped at token issuance, because
// FilterVisiblePermissions' server-level gate makes nothing under an unshared resource server
// visible. allRoots alone would not be enough either: it covers Root organization units only, so a
// child of a Root would still see nothing.
func (ts *ResourceScopeAuthzTestSuite) TestSystemResourceServerIsSharedDeploymentWide() {
	grants, err := testutils.ListResourceServerGrants(systemResourceServerID)
	ts.Require().NoError(err, "list the System resource server's own grants")

	var found bool
	for _, g := range grants {
		if g.TargetScope == "all_ous" {
			found = true
		}
	}
	ts.True(found, "bootstrap must leave an all_ous grant on the System resource server; got %+v", grants)
}

// TestScopedRoleInNonDefaultOUWorksEndToEnd is the regression test for the concrete failure that
// motivated the deployment-wide grant: a role created in an organization unit other than the one
// owning the System resource server, naming a system permission, must both be accepted at write
// time and have that permission actually stored.
//
// Both halves used to fail with ROL-1025, because FilterVisiblePermissions' server-level gate made
// nothing under the System resource server visible outside its owning organization unit.
//
// The permission under test is deliberately a NEW sub-resource of the System resource server, not
// its pre-existing top-level "system" resource: that top-level resource's derived permission is
// literally the deployment root permission string, which FilterVisiblePermissions keeps
// unconditionally as a categorical bypass (design doc section 4.4). Asserting on it would pass
// even with no grant at all and prove nothing. A sub-resource has an ordinary permission
// string with no bypass, so it exercises the real sharing path, and it is also the exact shape the
// Postman collection's scoped-administrator setup uses.
func (ts *ResourceScopeAuthzTestSuite) TestScopedRoleInNonDefaultOUWorksEndToEnd() {
	// A child of shareeOU, to prove the grant reaches descendants and not merely Root OUs.
	childOUID, err := testutils.CreateOrganizationUnit(testutils.OrganizationUnit{
		Handle:      "res-scope-authz-child-ou",
		Name:        "Resource Scope Authz Child OU",
		Description: "Child of the sharee OU, proving all_ous reaches descendants",
		Parent:      &ts.shareeOUID,
	})
	ts.Require().NoError(err)
	defer func() {
		if delErr := testutils.DeleteOrganizationUnit(childOUID); delErr != nil {
			ts.T().Logf("delete child OU: %v", delErr)
		}
	}()

	// Locate the System resource server's top-level "system" resource, then hang a sub-resource
	// off it exactly as the collection's scoped-administrator setup does. The sub-resource
	// auto-inherits its parent's grants at creation (design doc section 5.2), which only works if
	// the bootstrap grant actually cascaded to the parent resource in the first place.
	topLevel, err := listResources(systemResourceServerID, "", 0, 100)
	ts.Require().NoError(err, "list the System resource server's resources")
	var systemResourceID string
	for _, r := range topLevel.Resources {
		if r.Handle == "system" {
			systemResourceID = r.ID
		}
	}
	ts.Require().NotEmpty(systemResourceID, "the System resource server must have a 'system' resource")

	subResourceID, err := createResource(systemResourceServerID, CreateResourceRequest{
		Name:   "Scope Authz Probe",
		Handle: "res-scope-authz-probe",
		Parent: &systemResourceID,
	})
	ts.Require().NoError(err, "create a sub-resource under the System resource")
	defer func() {
		if delErr := deleteResource(systemResourceServerID, subResourceID); delErr != nil {
			ts.T().Logf("delete probe sub-resource: %v", delErr)
		}
	}()

	probe, err := getResource(systemResourceServerID, subResourceID)
	ts.Require().NoError(err)
	ts.Require().Equal("system:res-scope-authz-probe", probe.Permission,
		"the probe permission must be a real, non-bypass permission string")

	// It must have auto-inherited a grant from its parent; without that the role write below is
	// rejected no matter what the resource server's own grant says.
	subGrants, err := testutils.ListResourceGrants(systemResourceServerID, subResourceID)
	ts.Require().NoError(err)
	ts.NotEmpty(subGrants,
		"a new sub-resource must inherit the System resource server's deployment-wide grant")

	// A role in the CHILD OU (neither the owner nor a Root) naming that permission must be
	// accepted, and must actually keep it.
	roleID, err := testutils.CreateRole(testutils.Role{
		Name: "res-scope-authz-child-ou-role",
		OUID: childOUID,
		Permissions: []testutils.ResourcePermissions{
			{ResourceServerID: systemResourceServerID, Permissions: []string{probe.Permission}},
		},
	})
	ts.Require().NoError(err,
		"a role in a descendant OU naming a System sub-resource permission must be accepted "+
			"(ROL-1025 otherwise)")
	defer func() {
		if delErr := testutils.DeleteRole(roleID); delErr != nil {
			ts.T().Logf("delete child OU role: %v", delErr)
		}
	}()

	stored, err := testutils.GetRole(roleID)
	ts.Require().NoError(err)
	ts.Require().Len(stored.Permissions, 1)
	ts.Contains(stored.Permissions[0].Permissions, probe.Permission,
		"the permission must actually be stored on the role, not silently dropped")
}
