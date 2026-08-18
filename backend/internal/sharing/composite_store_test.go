// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package sharing

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

// CompositeSharingStoreTestSuite covers the merge of database-backed grants with the grants a
// declarative resource file declares, which are held in memory rather than persisted.
type CompositeSharingStoreTestSuite struct {
	suite.Suite
	dbStore     *sharingStoreInterfaceMock
	declarative *declarativeGrantStore
	store       *compositeSharingStore
}

func TestCompositeSharingStoreTestSuite(t *testing.T) {
	suite.Run(t, new(CompositeSharingStoreTestSuite))
}

func (suite *CompositeSharingStoreTestSuite) SetupTest() {
	suite.dbStore = newSharingStoreInterfaceMock(suite.T())
	suite.declarative = newDeclarativeGrantStore()
	suite.store = newCompositeSharingStore(suite.dbStore, suite.declarative)
}

// seedDeclarative records a declared grant for testRoleType on the given resource.
func (suite *CompositeSharingStoreTestSuite) seedDeclarative(id, resourceID string, targetOUID string) Grant {
	grant := Grant{
		ID:           id,
		ResourceType: "role",
		ResourceID:   resourceID,
		OwningOUID:   "owner-ou",
		Stage:        StageShare,
		TargetScope:  TargetScopeOU,
		TargetOUID:   targetOUID,
	}
	suite.declarative.Seed(grant)
	return grant
}

func (suite *CompositeSharingStoreTestSuite) TestCreateGrantAlwaysPersists() {
	grant := Grant{ID: "g1", ResourceType: "role", ResourceID: "role1"}
	suite.dbStore.On("CreateGrant", mock.Anything, grant).Return(nil)

	suite.NoError(suite.store.CreateGrant(context.Background(), grant))
}

func (suite *CompositeSharingStoreTestSuite) TestGetGrantFallsBackToDeclarative() {
	declared := suite.seedDeclarative("decl-1", "role1", "child-ou")
	suite.dbStore.On("GetGrant", mock.Anything, "decl-1").Return(Grant{}, ErrGrantNotFound)

	got, err := suite.store.GetGrant(context.Background(), "decl-1")

	suite.NoError(err)
	suite.Equal(declared, got)
}

func (suite *CompositeSharingStoreTestSuite) TestGetGrantPropagatesRealStoreError() {
	suite.dbStore.On("GetGrant", mock.Anything, "g1").Return(Grant{}, errors.New("db down"))

	_, err := suite.store.GetGrant(context.Background(), "g1")

	suite.Error(err)
	suite.False(errors.Is(err, ErrGrantNotFound))
}

func (suite *CompositeSharingStoreTestSuite) TestGetGrantNotFoundInEitherSource() {
	suite.dbStore.On("GetGrant", mock.Anything, "missing").Return(Grant{}, ErrGrantNotFound)

	_, err := suite.store.GetGrant(context.Background(), "missing")

	suite.ErrorIs(err, ErrGrantNotFound)
}

// A declared grant lives as long as the file that declares it; deleting it here would leave the
// running process disagreeing with the file, and it would come back on the next startup anyway.
func (suite *CompositeSharingStoreTestSuite) TestDeleteGrantRefusesDeclarative() {
	suite.seedDeclarative("decl-1", "role1", "child-ou")

	err := suite.store.DeleteGrant(context.Background(), "decl-1")

	suite.ErrorIs(err, ErrGrantDeclarative)
	suite.dbStore.AssertNotCalled(suite.T(), "DeleteGrant", mock.Anything, mock.Anything)
}

func (suite *CompositeSharingStoreTestSuite) TestDeleteGrantPassesThroughForStoredGrant() {
	suite.dbStore.On("DeleteGrant", mock.Anything, "g1").Return(nil)

	suite.NoError(suite.store.DeleteGrant(context.Background(), "g1"))
}

func (suite *CompositeSharingStoreTestSuite) TestListGrantsForResourceMergesBothSources() {
	stored := Grant{ID: "g1", ResourceType: "role", ResourceID: "role1"}
	suite.dbStore.On("ListGrantsForResource", mock.Anything, ResourceType("role"), "role1").
		Return([]Grant{stored}, nil)
	declared := suite.seedDeclarative("decl-1", "role1", "child-ou")
	// A declared grant on a different resource must not leak into this resource's list.
	suite.seedDeclarative("decl-2", "role2", "child-ou")

	grants, err := suite.store.ListGrantsForResource(context.Background(), "role", "role1")

	suite.NoError(err)
	suite.Equal([]Grant{stored, declared}, grants)
}

func (suite *CompositeSharingStoreTestSuite) TestCountGrantsForResourceCountsBothSources() {
	suite.dbStore.On("CountGrantsForResource", mock.Anything, ResourceType("role"), "role1").Return(2, nil)
	suite.seedDeclarative("decl-1", "role1", "child-ou")

	count, err := suite.store.CountGrantsForResource(context.Background(), "role", "role1")

	suite.NoError(err)
	suite.Equal(3, count)
}

// Paging happens over the merged set, since the database store cannot page across a second source.
func (suite *CompositeSharingStoreTestSuite) TestListGrantsForResourcePageSpansBothSources() {
	stored := []Grant{
		{ID: "g1", ResourceType: "role", ResourceID: "role1"},
		{ID: "g2", ResourceType: "role", ResourceID: "role1"},
	}
	suite.dbStore.On("ListGrantsForResource", mock.Anything, ResourceType("role"), "role1").
		Return(stored, nil)
	suite.seedDeclarative("decl-1", "role1", "child-ou")

	// A page straddling the boundary must return the last stored grant and the declared one.
	page, err := suite.store.ListGrantsForResourcePage(context.Background(), "role", "role1", 2, 1)

	suite.NoError(err)
	suite.Len(page, 2)
	suite.Equal("g2", page[0].ID)
	suite.Equal("decl-1", page[1].ID)
}

func (suite *CompositeSharingStoreTestSuite) TestListGrantsForResourcePageOffsetBeyondEnd() {
	suite.dbStore.On("ListGrantsForResource", mock.Anything, ResourceType("role"), "role1").
		Return([]Grant{{ID: "g1"}}, nil)

	page, err := suite.store.ListGrantsForResourcePage(context.Background(), "role", "role1", 10, 5)

	suite.NoError(err)
	suite.Empty(page)
}

// This is the read that decides visibility, so a declared grant participating here is what makes
// a declaratively granted role actually resolvable for the organization unit it was granted to.
func (suite *CompositeSharingStoreTestSuite) TestListGrantsRelevantToChainMergesBothSources() {
	stored := Grant{ID: "g1", ResourceType: "role", ResourceID: "role1", TargetOUID: "child-ou"}
	suite.dbStore.On("ListGrantsRelevantToChain", mock.Anything, ResourceType("role"), []string{"child-ou"}).
		Return([]Grant{stored}, nil)
	declared := suite.seedDeclarative("decl-1", "role2", "child-ou")
	// Targets an organization unit outside the chain, so it must not be returned.
	suite.seedDeclarative("decl-2", "role3", "other-ou")

	grants, err := suite.store.ListGrantsRelevantToChain(context.Background(), "role", []string{"child-ou"})

	suite.NoError(err)
	suite.Equal([]Grant{stored, declared}, grants)
}

func (suite *CompositeSharingStoreTestSuite) TestListGrantsRelevantToChainKeepsAllRootsGrants() {
	suite.dbStore.On("ListGrantsRelevantToChain", mock.Anything, ResourceType("role"), []string{"child-ou"}).
		Return([]Grant{}, nil)
	// An all_roots grant carries no target OU, so it can apply to any chain and is always relevant.
	suite.declarative.Seed(Grant{
		ID: "decl-all-roots", ResourceType: "role", ResourceID: "role1", TargetScope: TargetScopeAllRoots,
	})

	grants, err := suite.store.ListGrantsRelevantToChain(context.Background(), "role", []string{"child-ou"})

	suite.NoError(err)
	suite.Require().Len(grants, 1)
	suite.Equal("decl-all-roots", grants[0].ID)
}

func (suite *CompositeSharingStoreTestSuite) TestListChildGrantsMergesBothSources() {
	stored := Grant{ID: "g2", ParentGrantID: "g1"}
	suite.dbStore.On("ListChildGrants", mock.Anything, "g1").Return([]Grant{stored}, nil)
	suite.declarative.Seed(Grant{ID: "decl-child", ResourceType: "role", ParentGrantID: "g1"})

	grants, err := suite.store.ListChildGrants(context.Background(), "g1")

	suite.NoError(err)
	suite.Require().Len(grants, 2)
	suite.Equal("g2", grants[0].ID)
	suite.Equal("decl-child", grants[1].ID)
}

// An overlay is a sharee organization unit's own runtime edit, not something the file declares, so
// it is persisted even for a declarative resource.
func (suite *CompositeSharingStoreTestSuite) TestOverlaysPassThroughToDatabase() {
	ctx := context.Background()
	fields := map[string]string{"assignments": "[]"}
	suite.dbStore.On("SetOverlay", mock.Anything, ResourceType("role"), "role1", "child-ou", fields).Return(nil)
	suite.dbStore.On("GetOverlay", mock.Anything, ResourceType("role"), "role1", "child-ou").
		Return(fields, true, nil)
	suite.dbStore.On("DeleteOverlay", mock.Anything, ResourceType("role"), "role1", "child-ou").Return(nil)

	suite.NoError(suite.store.SetOverlay(ctx, "role", "role1", "child-ou", fields))
	got, found, err := suite.store.GetOverlay(ctx, "role", "role1", "child-ou")
	suite.NoError(err)
	suite.True(found)
	suite.Equal(fields, got)
	suite.NoError(suite.store.DeleteOverlay(ctx, "role", "role1", "child-ou"))
}

func (suite *CompositeSharingStoreTestSuite) TestDeclarativeLoadMarkerRoundTrips() {
	suite.False(isDeclarativeLoad(context.Background()))
	suite.True(isDeclarativeLoad(withDeclarativeLoad(context.Background())))
}
