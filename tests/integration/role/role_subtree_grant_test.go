// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/thunder-id/thunderid/tests/integration/testutils"
)

// roleListForOU mirrors the origin-tagged GET /roles?ouId= response.
type roleListForOU struct {
	TotalResults int `json:"totalResults"`
	Roles        []struct {
		ID     string `json:"id"`
		Origin string `json:"origin"`
	} `json:"roles"`
}

// RoleSubtreeGrantTestSuite covers the ou_subtree target scope: an ouIds entry carrying
// allChildren grants the named organization unit together with its whole branch, in one call.
//
// The tree is owner -> branch -> leaf, plus a sibling of branch under the same owner:
//
//	owner
//	├── branch
//	│   └── leaf
//	└── sibling
//
// which is the smallest shape that separates the three scopes: a plain entry naming branch
// reaches branch alone, this scope also reaches leaf, and only allChildren at the top level would
// reach sibling.
type RoleSubtreeGrantTestSuite struct {
	suite.Suite
	handleSuffix string
	ownerOUID    string
	branchOUID   string
	leafOUID     string
	siblingOUID  string
	roleID       string
	grantID      string
}

func TestRoleSubtreeGrantTestSuite(t *testing.T) {
	suite.Run(t, new(RoleSubtreeGrantTestSuite))
}

func (suite *RoleSubtreeGrantTestSuite) SetupSuite() {
	suite.handleSuffix = fmt.Sprintf("%d", time.Now().UnixNano())

	ownerOUID, err := testutils.CreateOrganizationUnit(testutils.OrganizationUnit{
		Handle: "sub-owner-" + suite.handleSuffix,
		Name:   "Subtree Grant Owner " + suite.handleSuffix,
	})
	suite.Require().NoError(err)
	suite.ownerOUID = ownerOUID

	branchOUID, err := testutils.CreateOrganizationUnit(testutils.OrganizationUnit{
		Handle: "sub-branch-" + suite.handleSuffix,
		Name:   "Subtree Grant Branch " + suite.handleSuffix,
		Parent: &ownerOUID,
	})
	suite.Require().NoError(err)
	suite.branchOUID = branchOUID

	leafOUID, err := testutils.CreateOrganizationUnit(testutils.OrganizationUnit{
		Handle: "sub-leaf-" + suite.handleSuffix,
		Name:   "Subtree Grant Leaf " + suite.handleSuffix,
		Parent: &branchOUID,
	})
	suite.Require().NoError(err)
	suite.leafOUID = leafOUID

	siblingOUID, err := testutils.CreateOrganizationUnit(testutils.OrganizationUnit{
		Handle: "sub-sibling-" + suite.handleSuffix,
		Name:   "Subtree Grant Sibling " + suite.handleSuffix,
		Parent: &ownerOUID,
	})
	suite.Require().NoError(err)
	suite.siblingOUID = siblingOUID

	roleID, err := testutils.CreateRole(testutils.Role{
		Name: "Subtree Grant Role " + suite.handleSuffix,
		OUID: ownerOUID,
	})
	suite.Require().NoError(err)
	suite.roleID = roleID

	// One call, one entry: branch and everything beneath it.
	grantID, err := testutils.ShareRole(roleID, map[string]interface{}{
		"initiatingOuId": ownerOUID,
		"ouIds": []map[string]interface{}{
			{"ouId": branchOUID, "allChildren": true},
		},
	})
	suite.Require().NoError(err)
	suite.grantID = grantID
}

func (suite *RoleSubtreeGrantTestSuite) TearDownSuite() {
	if suite.grantID != "" {
		if err := testutils.UnshareRole(suite.roleID, suite.grantID); err != nil {
			suite.T().Logf("Failed to unshare grant %s: %v", suite.grantID, err)
		}
	}
	if suite.roleID != "" {
		if err := testutils.DeleteRole(suite.roleID); err != nil {
			suite.T().Logf("Failed to delete role %s: %v", suite.roleID, err)
		}
	}
	// Deepest first: an OU cannot be deleted while it still has children.
	for _, ouID := range []string{suite.leafOUID, suite.branchOUID, suite.siblingOUID, suite.ownerOUID} {
		if ouID == "" {
			continue
		}
		if err := testutils.DeleteOrganizationUnit(ouID); err != nil {
			suite.T().Logf("Failed to delete OU %s: %v", ouID, err)
		}
	}
}

// seesRole reports whether ouID currently sees the suite's role, and with which origin.
func (suite *RoleSubtreeGrantTestSuite) seesRole(ouID string) (bool, string) {
	url := testServerURL + rolesBasePath + "?ouId=" + ouID
	req, err := http.NewRequest(http.MethodGet, url, nil)
	suite.Require().NoError(err)

	resp, err := testutils.GetHTTPClient().Do(req)
	suite.Require().NoError(err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err)
	suite.Require().Equal(http.StatusOK, resp.StatusCode, "body: %s", string(body))

	var list roleListForOU
	suite.Require().NoError(json.Unmarshal(body, &list), "body: %s", string(body))
	for _, r := range list.Roles {
		if r.ID == suite.roleID {
			return true, r.Origin
		}
	}
	return false, ""
}

// TestGrantIsRecordedAsOUSubtree proves the request shape maps to the new target scope rather
// than the plain ou scope a flag-less entry produces.
func (suite *RoleSubtreeGrantTestSuite) TestGrantIsRecordedAsOUSubtree() {
	url := testServerURL + rolesBasePath + "/" + suite.roleID + "/grants"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	suite.Require().NoError(err)

	resp, err := testutils.GetHTTPClient().Do(req)
	suite.Require().NoError(err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err)
	suite.Require().Equal(http.StatusOK, resp.StatusCode, "body: %s", string(body))

	var page grantsPage
	suite.Require().NoError(json.Unmarshal(body, &page), "body: %s", string(body))
	suite.Require().Len(page.Grants, 1)
	suite.Equal("ou_subtree", page.Grants[0].TargetScope)
	suite.Equal(suite.branchOUID, page.Grants[0].TargetOUID)
	suite.Equal("share", page.Grants[0].Stage,
		"the role's own owner issued this, so it is a first-hop grant regardless of target mode")
}

// TestNamedBranchSeesTheRole covers the anchor itself, which a plain ou grant would also reach.
func (suite *RoleSubtreeGrantTestSuite) TestNamedBranchSeesTheRole() {
	seen, origin := suite.seesRole(suite.branchOUID)

	suite.True(seen, "the named organization unit must see the role")
	suite.Equal("shared", origin)
}

// TestLeafBeneathBranchSeesTheRole is the capability itself: one grant from the owner reaches two
// levels down, with no second call from branch. Under a flag-less entry this organization unit
// would see nothing until branch issued its own grant.
func (suite *RoleSubtreeGrantTestSuite) TestLeafBeneathBranchSeesTheRole() {
	seen, origin := suite.seesRole(suite.leafOUID)

	suite.True(seen, "an organization unit beneath the named branch must be covered by the same grant")
	suite.Equal("shared", origin)
}

// TestSiblingBranchDoesNotSeeTheRole is the counterweight: the grant reaches one named branch, not
// every branch the owner has. Without this, the scope would be indistinguishable from allChildren.
func (suite *RoleSubtreeGrantTestSuite) TestSiblingBranchDoesNotSeeTheRole() {
	seen, _ := suite.seesRole(suite.siblingOUID)

	suite.False(seen, "a branch outside the granted one must not be reached")
}

// TestNewChildIsCoveredWithoutANewGrant proves the subtree is resolved dynamically rather than
// snapshotted at grant time, matching allChildren's own behaviour.
func (suite *RoleSubtreeGrantTestSuite) TestNewChildIsCoveredWithoutANewGrant() {
	lateOUID, err := testutils.CreateOrganizationUnit(testutils.OrganizationUnit{
		Handle: "sub-late-" + suite.handleSuffix,
		Name:   "Subtree Grant Late Child " + suite.handleSuffix,
		Parent: &suite.leafOUID,
	})
	suite.Require().NoError(err)
	defer func() {
		if err := testutils.DeleteOrganizationUnit(lateOUID); err != nil {
			suite.T().Logf("Failed to delete OU %s: %v", lateOUID, err)
		}
	}()

	seen, origin := suite.seesRole(lateOUID)

	suite.True(seen, "an organization unit created after the grant must still be covered")
	suite.Equal("shared", origin)
}
