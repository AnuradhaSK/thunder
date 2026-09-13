// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/thunder-id/thunderid/tests/integration/testutils"
)

// M2MOUScopedScopesTestSuite proves the division of labour between the two organization units
// involved in an OU-scoped token request:
//
//   - What the application is *entitled* to is resolved from its own owning organization unit,
//     through the role assigned to it there. That answer does not change with the accessing OU.
//   - What the token may actually *carry* is then narrowed to the permissions the accessing
//     organization unit can see, which is decided by the resource-server grants made to it.
//
// The fixture grants the resource server to a child organization unit while excluding one of its
// two resources, so the same credential and the same requested scopes yield a different scope set
// depending on which organization unit the token is requested against.
type M2MOUScopedScopesTestSuite struct {
	suite.Suite
	rsID         string
	rsIdentifier string
	ordersResID  string
	roleID       string
	grantIDs     []string
}

func TestM2MOUScopedScopesTestSuite(t *testing.T) {
	suite.Run(t, new(M2MOUScopedScopesTestSuite))
}

const (
	scopeBooksRead   = "books:read"
	scopeBooksCreate = "books:create"
	scopeOrdersRead  = "orders:read"
)

func (suite *M2MOUScopedScopesTestSuite) SetupSuite() {
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	suite.rsIdentifier = "https://m2m-scopes-" + suffix + ".example.com"

	// Owned by the same organization unit that owns the declarative M2M applications.
	rsID, err := testutils.CreateResourceServerWithActions(testutils.ResourceServer{
		Name:       "M2M Scope Filter RS " + suffix,
		Identifier: suite.rsIdentifier,
		OUID:       m2mRootOUID,
	}, nil)
	suite.Require().NoError(err, "create resource server")
	suite.rsID = rsID

	booksID := suite.createResource(rsID, "Books", "books")
	suite.createAction(rsID, booksID, "Read", "read")
	suite.createAction(rsID, booksID, "Create", "create")

	// The resource deliberately withheld from the child organization unit.
	suite.ordersResID = suite.createResource(rsID, "Orders", "orders")
	suite.createAction(rsID, suite.ordersResID, "Read", "read")

	// The application's entitlement lives in its own owning organization unit: a role there,
	// carrying every permission, assigned directly to the application.
	roleID, err := testutils.CreateRole(testutils.Role{
		Name: "M2M Scope Filter Role " + suffix,
		OUID: m2mRootOUID,
		Permissions: []testutils.ResourcePermissions{{
			ResourceServerID: rsID,
			Permissions:      []string{scopeBooksRead, scopeBooksCreate, scopeOrdersRead},
		}},
		Assignments: []testutils.Assignment{{ID: m2mSubtreeAppID, Type: "app"}},
	})
	suite.Require().NoError(err, "create role")
	suite.roleID = roleID

	// Grant the resource server to the child, withholding the orders resource. The cascade would
	// otherwise reach every resource and action beneath the server.
	grants, err := testutils.ShareResourceServer(rsID, map[string]interface{}{
		"ouIds":           []string{m2mChildAOUID},
		"excludedNodeIds": []string{suite.ordersResID},
	})
	suite.Require().NoError(err, "grant resource server to child, excluding orders")
	// Server + books + books's two actions. Neither the excluded orders resource nor the action
	// beneath it is granted: excluding a node excludes its subtree, otherwise every permission the
	// withheld resource defines would stay visible.
	suite.Require().Len(grants, 4, "cascade must cover the server, books, and books's two actions only")
	for _, g := range grants {
		suite.grantIDs = append(suite.grantIDs, g.ID)
	}
}

func (suite *M2MOUScopedScopesTestSuite) TearDownSuite() {
	if suite.roleID != "" {
		if err := testutils.DeleteRole(suite.roleID); err != nil {
			suite.T().Logf("teardown: delete role: %v", err)
		}
	}
	if suite.rsID != "" {
		if err := testutils.DeleteResourceServerWithChildren(suite.rsID); err != nil {
			suite.T().Logf("teardown: delete resource server: %v", err)
		}
	}
}

func (suite *M2MOUScopedScopesTestSuite) createResource(rsID, name, handle string) string {
	suite.T().Helper()
	body, _ := json.Marshal(map[string]interface{}{"name": name, "handle": handle})
	return suite.postForID(fmt.Sprintf("%s/resource-servers/%s/resources", testutils.TestServerURL, rsID), body)
}

func (suite *M2MOUScopedScopesTestSuite) createAction(rsID, resourceID, name, handle string) string {
	suite.T().Helper()
	body, _ := json.Marshal(map[string]interface{}{"name": name, "handle": handle})
	return suite.postForID(
		fmt.Sprintf("%s/resource-servers/%s/resources/%s/actions", testutils.TestServerURL, rsID, resourceID), body)
}

func (suite *M2MOUScopedScopesTestSuite) postForID(url string, body []byte) string {
	suite.T().Helper()
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	suite.Require().NoError(err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := testutils.GetHTTPClient().Do(req)
	suite.Require().NoError(err)
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err)
	suite.Require().Equal(http.StatusCreated, resp.StatusCode, "body: %s", string(raw))

	var created struct {
		ID string `json:"id"`
	}
	suite.Require().NoError(json.Unmarshal(raw, &created))
	suite.Require().NotEmpty(created.ID)
	return created.ID
}

// requestScopedToken asks for a token bound to the fixture's resource server, optionally against an
// accessing organization unit, and returns the scopes the server actually granted.
func (suite *M2MOUScopedScopesTestSuite) requestScopedToken(ouID string) (int, []string) {
	suite.T().Helper()

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", strings.Join([]string{scopeBooksRead, scopeBooksCreate, scopeOrdersRead}, " "))
	form.Set("resource", suite.rsIdentifier)

	endpoint := testutils.TestServerURL + "/oauth2/token"
	if ouID != "" {
		endpoint = testutils.TestServerURL + "/ou/" + ouID + "/oauth2/token"
	}

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(form.Encode()))
	suite.Require().NoError(err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(m2mSubtreeClientID, m2mSubtreeSecret)

	// Raw client: this test authenticates as an OAuth client and owns its Authorization header.
	resp, err := testutils.GetRawHTTPClient().Do(req)
	suite.Require().NoError(err)
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err)

	var parsed struct {
		Scope string `json:"scope"`
	}
	_ = json.Unmarshal(raw, &parsed)
	if resp.StatusCode != http.StatusOK {
		suite.T().Logf("token request for ou=%q returned %d: %s", ouID, resp.StatusCode, string(raw))
		return resp.StatusCode, nil
	}

	scopes := strings.Fields(parsed.Scope)
	sort.Strings(scopes)
	return resp.StatusCode, scopes
}

// TestOwningOUGetsEveryEntitledScope establishes the baseline: against its own organization unit the
// application carries everything its role grants, since the owner sees its own resource server whole.
func (suite *M2MOUScopedScopesTestSuite) TestOwningOUGetsEveryEntitledScope() {
	status, scopes := suite.requestScopedToken(m2mRootOUID)

	suite.Equal(http.StatusOK, status)
	suite.Equal([]string{scopeBooksCreate, scopeBooksRead, scopeOrdersRead}, scopes)
}

// TestAccessingOUOnlyGetsGrantedScopes is the point of the feature: the same credential, the same
// role, and the same requested scopes yield a narrower token against the child, because the orders
// resource was withheld from it when the resource server was granted.
func (suite *M2MOUScopedScopesTestSuite) TestAccessingOUOnlyGetsGrantedScopes() {
	status, scopes := suite.requestScopedToken(m2mChildAOUID)

	suite.Equal(http.StatusOK, status)
	suite.Equal([]string{scopeBooksCreate, scopeBooksRead}, scopes,
		"orders:read must be filtered out: the child was never granted the orders resource")
	suite.NotContains(scopes, scopeOrdersRead)
}

// TestBareEndpointIsUnaffected pins that scope filtering only engages when an accessing organization
// unit is named; without one, issuance resolves against the application's own organization unit
// exactly as it did before.
func (suite *M2MOUScopedScopesTestSuite) TestBareEndpointIsUnaffected() {
	status, scopes := suite.requestScopedToken("")

	suite.Equal(http.StatusOK, status)
	suite.Equal([]string{scopeBooksCreate, scopeBooksRead, scopeOrdersRead}, scopes)
}
