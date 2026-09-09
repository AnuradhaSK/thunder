// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/thunder-id/thunderid/tests/integration/testutils"
)

// ResourceSharingTestSuite covers the tree-shaped orchestration this feature adds on top of the
// generic role-sharing framework: cascade share/unshare across a resource server's tree, cascade
// exclusion, leaf actions never cascading, and auto-inherit-on-creation.
//
// Every test method builds and tears down its own resource server so cascade operations (which can
// fan out to "every resource/action currently under" a node) never interact with a sibling test's
// fixtures.
type ResourceSharingTestSuite struct {
	suite.Suite

	ownerOUID  string
	shareeOUID string
	otherOUID  string
}

func TestResourceSharingTestSuite(t *testing.T) {
	suite.Run(t, new(ResourceSharingTestSuite))
}

func (suite *ResourceSharingTestSuite) SetupSuite() {
	ownerID, err := testutils.CreateOrganizationUnit(testutils.OrganizationUnit{
		Handle:      "res-sharing-owner-ou",
		Name:        "Resource Sharing Owner OU",
		Description: "Owns every resource server built by ResourceSharingTestSuite",
	})
	suite.Require().NoError(err, "Failed to create owner OU")
	suite.ownerOUID = ownerID

	shareeID, err := testutils.CreateOrganizationUnit(testutils.OrganizationUnit{
		Handle:      "res-sharing-sharee-ou",
		Name:        "Resource Sharing Sharee OU",
		Description: "Target OU for cascade share operations",
	})
	suite.Require().NoError(err, "Failed to create sharee OU")
	suite.shareeOUID = shareeID

	otherID, err := testutils.CreateOrganizationUnit(testutils.OrganizationUnit{
		Handle:      "res-sharing-other-ou",
		Name:        "Resource Sharing Other OU",
		Description: "A second, independent target OU used to prove cascade unshare only revokes its own selection",
	})
	suite.Require().NoError(err, "Failed to create other OU")
	suite.otherOUID = otherID
}

func (suite *ResourceSharingTestSuite) TearDownSuite() {
	for _, id := range []string{suite.otherOUID, suite.shareeOUID, suite.ownerOUID} {
		if id != "" {
			if err := testutils.DeleteOrganizationUnit(id); err != nil {
				suite.T().Logf("Failed to delete OU %s: %v", id, err)
			}
		}
	}
}

// findGrant returns the first grant of the given nodeType/nodeId in grants, failing the test if
// none is found.
func (suite *ResourceSharingTestSuite) findGrant(
	grants []testutils.ResourceGrant, nodeType, nodeID string,
) testutils.ResourceGrant {
	suite.T().Helper()
	for _, g := range grants {
		if g.NodeType == nodeType && g.NodeID == nodeID {
			return g
		}
	}
	suite.FailNowf("grant not found", "no grant for nodeType=%s nodeId=%s in %+v", nodeType, nodeID, grants)
	return testutils.ResourceGrant{}
}

// TestCascadeShare_ResourceServerCascadesToDescendants verifies sharing a resource server creates
// grants not just for the server itself but for every resource and action currently beneath it,
// and that each node's own GET .../grants confirms it independently (behavior 1).
func (suite *ResourceSharingTestSuite) TestCascadeShare_ResourceServerCascadesToDescendants() {
	rsID, err := createResourceServer(CreateResourceServerRequest{
		Name: "Cascade Server Test RS",
		OUID: suite.ownerOUID,
	})
	suite.Require().NoError(err)
	defer deleteResourceServer(rsID)

	reportsID, err := createResource(rsID, CreateResourceRequest{Name: "Reports", Handle: "reports"})
	suite.Require().NoError(err)
	defer deleteResource(rsID, reportsID)

	viewID, err := createActionAtResource(rsID, reportsID, CreateActionRequest{Name: "View", Handle: "view"})
	suite.Require().NoError(err)
	defer deleteActionAtResource(rsID, reportsID, viewID)

	grants, err := testutils.ShareResourceServer(rsID, map[string]interface{}{
		"rootOuIds": []string{suite.shareeOUID},
	})
	suite.Require().NoError(err, "Failed to share resource server")
	suite.Require().Len(grants, 3, "cascade share must create one grant for the server, the resource, and the action")

	serverGrant := suite.findGrant(grants, "resource_server", rsID)
	resourceGrant := suite.findGrant(grants, "resource", reportsID)
	actionGrant := suite.findGrant(grants, "action", viewID)
	defer testutils.UnshareResourceServerGrant(rsID, serverGrant.ID)

	for _, g := range []testutils.ResourceGrant{serverGrant, resourceGrant, actionGrant} {
		suite.Equal("root", g.TargetScope)
		suite.Equal(suite.shareeOUID, g.TargetOUID)
		suite.Equal(suite.ownerOUID, g.OwningOUID)
	}

	// Verify independently via each node's own listing, not just the POST response.
	serverGrants, err := testutils.ListResourceServerGrants(rsID)
	suite.Require().NoError(err)
	suite.Len(serverGrants, 1)

	resourceGrants, err := testutils.ListResourceGrants(rsID, reportsID)
	suite.Require().NoError(err)
	suite.Len(resourceGrants, 1)

	actionGrants, err := testutils.ListActionGrants(rsID, reportsID, viewID)
	suite.Require().NoError(err)
	suite.Len(actionGrants, 1)
}

// TestCascadeShare_ExcludedNodeIsNotShared verifies excludedNodeIds carves a specific descendant
// out of an otherwise-cascading share: sharing a resource with one action excluded creates grants
// for the resource and its other action, but none for the excluded action (behavior 2).
func (suite *ResourceSharingTestSuite) TestCascadeShare_ExcludedNodeIsNotShared() {
	rsID, err := createResourceServer(CreateResourceServerRequest{
		Name: "Cascade Exclusion Test RS",
		OUID: suite.ownerOUID,
	})
	suite.Require().NoError(err)
	defer deleteResourceServer(rsID)

	bookingsID, err := createResource(rsID, CreateResourceRequest{Name: "Bookings", Handle: "bookings"})
	suite.Require().NoError(err)
	defer deleteResource(rsID, bookingsID)

	viewID, err := createActionAtResource(rsID, bookingsID, CreateActionRequest{Name: "View", Handle: "view"})
	suite.Require().NoError(err)
	defer deleteActionAtResource(rsID, bookingsID, viewID)

	createID, err := createActionAtResource(rsID, bookingsID, CreateActionRequest{Name: "Create", Handle: "create"})
	suite.Require().NoError(err)
	defer deleteActionAtResource(rsID, bookingsID, createID)

	grants, err := testutils.ShareResource(rsID, bookingsID, map[string]interface{}{
		"rootOuIds":       []string{suite.shareeOUID},
		"excludedNodeIds": []string{createID},
	})
	suite.Require().NoError(err, "Failed to share resource with an exclusion")
	suite.Require().Len(grants, 2, "the excluded action must not receive a grant")

	resourceGrant := suite.findGrant(grants, "resource", bookingsID)
	suite.findGrant(grants, "action", viewID) // must exist; fails the test if missing
	defer testutils.UnshareResourceGrant(rsID, bookingsID, resourceGrant.ID)

	for _, g := range grants {
		suite.NotEqual(createID, g.NodeID, "excluded action must not appear in the created grants")
	}

	createGrants, err := testutils.ListActionGrants(rsID, bookingsID, createID)
	suite.Require().NoError(err)
	suite.Empty(createGrants, "excluded action must have no grant")

	viewGrants, err := testutils.ListActionGrants(rsID, bookingsID, viewID)
	suite.Require().NoError(err)
	suite.Len(viewGrants, 1, "non-excluded action must still be shared")
}

// TestLeafActionShare_NoCascade verifies sharing a leaf action directly creates exactly one grant
// and never reaches a sibling action (behavior 3).
func (suite *ResourceSharingTestSuite) TestLeafActionShare_NoCascade() {
	rsID, err := createResourceServer(CreateResourceServerRequest{
		Name: "Leaf Action Share Test RS",
		OUID: suite.ownerOUID,
	})
	suite.Require().NoError(err)
	defer deleteResourceServer(rsID)

	bookingsID, err := createResource(rsID, CreateResourceRequest{Name: "Bookings", Handle: "bookings"})
	suite.Require().NoError(err)
	defer deleteResource(rsID, bookingsID)

	viewID, err := createActionAtResource(rsID, bookingsID, CreateActionRequest{Name: "View", Handle: "view"})
	suite.Require().NoError(err)
	defer deleteActionAtResource(rsID, bookingsID, viewID)

	createID, err := createActionAtResource(rsID, bookingsID, CreateActionRequest{Name: "Create", Handle: "create"})
	suite.Require().NoError(err)
	defer deleteActionAtResource(rsID, bookingsID, createID)

	grants, err := testutils.ShareAction(rsID, bookingsID, viewID, map[string]interface{}{
		"rootOuIds": []string{suite.shareeOUID},
	})
	suite.Require().NoError(err, "Failed to share leaf action")
	suite.Require().Len(grants, 1, "sharing a leaf action must create exactly one grant")
	suite.Equal(viewID, grants[0].NodeID)
	defer testutils.UnshareActionGrant(rsID, bookingsID, viewID, grants[0].ID)

	createGrants, err := testutils.ListActionGrants(rsID, bookingsID, createID)
	suite.Require().NoError(err)
	suite.Empty(createGrants, "sharing one action must never reach its sibling")
}

// TestAutoInherit_NewChildInheritsParentShare verifies that once a node is shared, a new child
// created under it afterward automatically shows up in the child's own grants listing, with
// no separate share call, and that this inheritance itself cascades transitively: a resource newly
// created under an already-shared resource server inherits the server's grant, and an action then
// created under that resource inherits the resource's (inherited) grant (behavior 4).
func (suite *ResourceSharingTestSuite) TestAutoInherit_NewChildInheritsParentShare() {
	rsID, err := createResourceServer(CreateResourceServerRequest{
		Name: "Auto Inherit Test RS",
		OUID: suite.ownerOUID,
	})
	suite.Require().NoError(err)
	defer deleteResourceServer(rsID)

	serverGrants, err := testutils.ShareResourceServer(rsID, map[string]interface{}{
		"rootOuIds": []string{suite.shareeOUID},
	})
	suite.Require().NoError(err, "Failed to share the (still-empty) resource server")
	suite.Require().Len(serverGrants, 1, "an empty server has no descendants to cascade to yet")
	defer testutils.UnshareResourceServerGrant(rsID, serverGrants[0].ID)

	// A brand new top-level resource, created after the server was shared, must inherit that share
	// immediately.
	reportsID, err := createResource(rsID, CreateResourceRequest{Name: "Reports", Handle: "reports"})
	suite.Require().NoError(err)
	defer deleteResource(rsID, reportsID)

	resourceGrants, err := testutils.ListResourceGrants(rsID, reportsID)
	suite.Require().NoError(err)
	suite.Require().Len(resourceGrants, 1, "new resource must auto-inherit the server's share")
	suite.Equal(suite.shareeOUID, resourceGrants[0].TargetOUID)

	// A new action created under that just-auto-shared resource must, in turn, inherit the
	// resource's (itself inherited) grant.
	viewID, err := createActionAtResource(rsID, reportsID, CreateActionRequest{Name: "View", Handle: "view"})
	suite.Require().NoError(err)
	defer deleteActionAtResource(rsID, reportsID, viewID)

	actionGrants, err := testutils.ListActionGrants(rsID, reportsID, viewID)
	suite.Require().NoError(err)
	suite.Require().Len(actionGrants, 1, "new action must auto-inherit its parent resource's share")
	suite.Equal(suite.shareeOUID, actionGrants[0].TargetOUID)
}

// TestCascadeUnshare_RevokesDescendantsButPreservesIndependentGrant verifies revoking a cascade
// share's top-level grant also revokes every descendant grant created alongside it, while a grant
// on a descendant created by a separate, independent share call (targeting a different OU) survives
// (behavior 5).
func (suite *ResourceSharingTestSuite) TestCascadeUnshare_RevokesDescendantsButPreservesIndependentGrant() {
	rsID, err := createResourceServer(CreateResourceServerRequest{
		Name: "Cascade Unshare Test RS",
		OUID: suite.ownerOUID,
	})
	suite.Require().NoError(err)
	defer deleteResourceServer(rsID)

	bookingsID, err := createResource(rsID, CreateResourceRequest{Name: "Bookings", Handle: "bookings"})
	suite.Require().NoError(err)
	defer deleteResource(rsID, bookingsID)

	viewID, err := createActionAtResource(rsID, bookingsID, CreateActionRequest{Name: "View", Handle: "view"})
	suite.Require().NoError(err)
	defer deleteActionAtResource(rsID, bookingsID, viewID)

	createID, err := createActionAtResource(rsID, bookingsID, CreateActionRequest{Name: "Create", Handle: "create"})
	suite.Require().NoError(err)
	defer deleteActionAtResource(rsID, bookingsID, createID)

	// Cascade share the resource to the sharee OU: grants for bookings, view, and create.
	cascadeGrants, err := testutils.ShareResource(rsID, bookingsID, map[string]interface{}{
		"rootOuIds": []string{suite.shareeOUID},
	})
	suite.Require().NoError(err)
	suite.Require().Len(cascadeGrants, 3)
	resourceGrant := suite.findGrant(cascadeGrants, "resource", bookingsID)

	// A second, independent share of the "create" action alone, to a different OU. This must
	// survive the cascade unshare below: it targets a different OU selection entirely, so it was
	// never part of the cascade being revoked.
	independentGrants, err := testutils.ShareAction(rsID, bookingsID, createID, map[string]interface{}{
		"rootOuIds": []string{suite.otherOUID},
	})
	suite.Require().NoError(err)
	suite.Require().Len(independentGrants, 1)
	independentGrant := independentGrants[0]

	// Revoke the top-level (bookings) grant of the original cascade.
	suite.Require().NoError(testutils.UnshareResourceGrant(rsID, bookingsID, resourceGrant.ID))

	resourceGrantsAfter, err := testutils.ListResourceGrants(rsID, bookingsID)
	suite.Require().NoError(err)
	suite.Empty(resourceGrantsAfter, "the resource's own grant must be revoked")

	viewGrantsAfter, err := testutils.ListActionGrants(rsID, bookingsID, viewID)
	suite.Require().NoError(err)
	suite.Empty(viewGrantsAfter, "the view action's cascade grant must be revoked along with its parent")

	createGrantsAfter, err := testutils.ListActionGrants(rsID, bookingsID, createID)
	suite.Require().NoError(err)
	suite.Require().Len(createGrantsAfter, 1,
		"the create action's independently-targeted grant must survive the cascade unshare")
	suite.Equal(independentGrant.ID, createGrantsAfter[0].ID)
	suite.Equal(suite.otherOUID, createGrantsAfter[0].TargetOUID)

	suite.Require().NoError(testutils.UnshareActionGrant(rsID, bookingsID, createID, independentGrant.ID))
}
