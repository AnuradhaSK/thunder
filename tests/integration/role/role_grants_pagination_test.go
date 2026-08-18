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

// grantsPage mirrors the paginated GET /roles/{id}/grants response.
type grantsPage struct {
	TotalResults int `json:"totalResults"`
	StartIndex   int `json:"startIndex"`
	Count        int `json:"count"`
	Grants       []struct {
		ID          string `json:"id"`
		Stage       string `json:"stage"`
		TargetScope string `json:"targetScope"`
		TargetOUID  string `json:"targetOuId"`
	} `json:"grants"`
	Links []struct {
		Href string `json:"href"`
		Rel  string `json:"rel"`
	} `json:"links"`
}

// RoleGrantsPaginationTestSuite covers pagination on GET /roles/{id}/grants. The role
// is shared to five separate root OUs, giving five grants to page through.
type RoleGrantsPaginationTestSuite struct {
	suite.Suite
	handleSuffix string
	roleID       string
	ouIDs        []string
	grantIDs     []string
}

func TestRoleGrantsPaginationTestSuite(t *testing.T) {
	suite.Run(t, new(RoleGrantsPaginationTestSuite))
}

func (suite *RoleGrantsPaginationTestSuite) SetupSuite() {
	suite.handleSuffix = fmt.Sprintf("%d", time.Now().UnixNano())

	ownerOUID, err := testutils.CreateOrganizationUnit(testutils.OrganizationUnit{
		Handle: "sg-page-owner-" + suite.handleSuffix,
		Name:   "Grant Paging Owner " + suite.handleSuffix,
	})
	suite.Require().NoError(err)
	suite.ouIDs = append(suite.ouIDs, ownerOUID)

	roleID, err := testutils.CreateRole(testutils.Role{
		Name: "Grant Paging Role " + suite.handleSuffix,
		OUID: ownerOUID,
	})
	suite.Require().NoError(err)
	suite.roleID = roleID

	for i := 0; i < 5; i++ {
		targetOUID, err := testutils.CreateOrganizationUnit(testutils.OrganizationUnit{
			Handle: fmt.Sprintf("sg-page-target-%d-%s", i, suite.handleSuffix),
			Name:   fmt.Sprintf("Grant Paging Target %d %s", i, suite.handleSuffix),
		})
		suite.Require().NoError(err)
		suite.ouIDs = append(suite.ouIDs, targetOUID)

		grantID, err := testutils.ShareRole(roleID, map[string]interface{}{
			"rootOuIds": []string{targetOUID},
		})
		suite.Require().NoError(err)
		suite.grantIDs = append(suite.grantIDs, grantID)
	}
}

func (suite *RoleGrantsPaginationTestSuite) TearDownSuite() {
	for _, grantID := range suite.grantIDs {
		if err := testutils.UnshareRole(suite.roleID, grantID); err != nil {
			suite.T().Logf("Failed to unshare grant %s: %v", grantID, err)
		}
	}
	if suite.roleID != "" {
		if err := testutils.DeleteRole(suite.roleID); err != nil {
			suite.T().Logf("Failed to delete role %s: %v", suite.roleID, err)
		}
	}
	// Targets first, owner last: the owner OU was created before them and nothing nests here, but
	// deleting in reverse creation order keeps this correct if that ever changes.
	for i := len(suite.ouIDs) - 1; i >= 0; i-- {
		if err := testutils.DeleteOrganizationUnit(suite.ouIDs[i]); err != nil {
			suite.T().Logf("Failed to delete OU %s: %v", suite.ouIDs[i], err)
		}
	}
}

// listGrants issues GET /roles/{id}/grants with the given query string and returns the
// decoded page alongside the HTTP status.
func (suite *RoleGrantsPaginationTestSuite) listGrants(query string) (grantsPage, int) {
	url := testServerURL + rolesBasePath + "/" + suite.roleID + "/grants" + query
	req, err := http.NewRequest(http.MethodGet, url, nil)
	suite.Require().NoError(err)

	resp, err := testutils.GetHTTPClient().Do(req)
	suite.Require().NoError(err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err)

	var page grantsPage
	if resp.StatusCode == http.StatusOK {
		suite.Require().NoError(json.Unmarshal(body, &page), "body: %s", string(body))
	}
	return page, resp.StatusCode
}

// TestDefaultPageReturnsEverythingWithTotal proves the endpoint stays usable without query
// parameters: the default page holds all five grants and reports the total.
func (suite *RoleGrantsPaginationTestSuite) TestDefaultPageReturnsEverythingWithTotal() {
	page, status := suite.listGrants("")

	suite.Equal(http.StatusOK, status)
	suite.Equal(5, page.TotalResults)
	suite.Equal(1, page.StartIndex)
	suite.Equal(5, page.Count)
	suite.Len(page.Grants, 5)
	suite.Empty(page.Links, "a single page holding every grant needs no navigation links")
}

// TestPagesCoverEveryGrantExactlyOnce walks the whole list two at a time and proves the pages
// partition it: no grant is skipped and none is returned twice.
func (suite *RoleGrantsPaginationTestSuite) TestPagesCoverEveryGrantExactlyOnce() {
	seen := make(map[string]int)
	expectedCounts := []int{2, 2, 1}

	for i, offset := range []int{0, 2, 4} {
		page, status := suite.listGrants(fmt.Sprintf("?limit=2&offset=%d", offset))

		suite.Equal(http.StatusOK, status)
		suite.Equal(5, page.TotalResults)
		suite.Equal(offset+1, page.StartIndex)
		suite.Equal(expectedCounts[i], page.Count)
		suite.Len(page.Grants, expectedCounts[i])

		for _, g := range page.Grants {
			seen[g.ID]++
		}
	}

	suite.Len(seen, 5, "every grant must appear exactly once across the pages")
	for id, count := range seen {
		suite.Equal(1, count, "grant %s appeared %d times across pages", id, count)
	}
	for _, grantID := range suite.grantIDs {
		suite.Contains(seen, grantID)
	}
}

// TestPaginationLinks proves the navigation links are emitted for a middle page and point back at
// this endpoint.
func (suite *RoleGrantsPaginationTestSuite) TestPaginationLinks() {
	page, status := suite.listGrants("?limit=2&offset=2")

	suite.Equal(http.StatusOK, status)
	rels := make([]string, 0, len(page.Links))
	for _, l := range page.Links {
		rels = append(rels, l.Rel)
		suite.Contains(l.Href, "/roles/"+suite.roleID+"/grants")
	}
	suite.ElementsMatch([]string{"first", "prev", "next", "last"}, rels)
}

// TestOffsetPastEndReturnsEmptyPage proves an offset beyond the last grant is an empty page with a
// correct total, not an error and not a wrapped-around first page.
func (suite *RoleGrantsPaginationTestSuite) TestOffsetPastEndReturnsEmptyPage() {
	page, status := suite.listGrants("?limit=2&offset=50")

	suite.Equal(http.StatusOK, status)
	suite.Equal(5, page.TotalResults)
	suite.Equal(0, page.Count)
	suite.Empty(page.Grants)
}

// TestInvalidPaginationParameters proves bad paging input is rejected with the same error codes the
// other paginated role endpoints use, rather than being silently coerced.
func (suite *RoleGrantsPaginationTestSuite) TestInvalidPaginationParameters() {
	for _, tc := range []struct{ name, query string }{
		{"non-numeric limit", "?limit=abc"},
		{"limit above max", "?limit=1000"},
		{"negative offset", "?offset=-1"},
	} {
		suite.Run(tc.name, func() {
			_, status := suite.listGrants(tc.query)
			suite.Equal(http.StatusBadRequest, status)
		})
	}
}
