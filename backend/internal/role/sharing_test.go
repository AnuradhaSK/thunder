// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"

	"github.com/thunder-id/thunderid/internal/group"
	oupkg "github.com/thunder-id/thunderid/internal/ou"
	"github.com/thunder-id/thunderid/internal/sharing"
	"github.com/thunder-id/thunderid/tests/mocks/entitymock"
	"github.com/thunder-id/thunderid/tests/mocks/groupmock"
	"github.com/thunder-id/thunderid/tests/mocks/sharingmock"
)

const (
	testOwnerOU        = "ou-owner"
	testShareeOU       = "ou-sharee"
	testAppSharingType = sharing.ResourceType("application")
)

type RoleSharingTestSuite struct {
	suite.Suite
	mockStore          *roleStoreInterfaceMock
	mockEntityService  *entitymock.EntityServiceInterfaceMock
	mockGroupService   *groupmock.GroupServiceInterfaceMock
	mockSharingService *sharingmock.SharingServiceInterfaceMock
	scope              *roleAssignmentScope
	ctx                context.Context
}

func TestRoleSharingTestSuite(t *testing.T) {
	suite.Run(t, new(RoleSharingTestSuite))
}

func (suite *RoleSharingTestSuite) SetupTest() {
	suite.mockStore = newRoleStoreInterfaceMock(suite.T())
	suite.mockEntityService = entitymock.NewEntityServiceInterfaceMock(suite.T())
	suite.mockGroupService = groupmock.NewGroupServiceInterfaceMock(suite.T())
	suite.mockSharingService = sharingmock.NewSharingServiceInterfaceMock(suite.T())
	suite.scope = newRoleAssignmentScope(suite.mockSharingService, suite.mockEntityService, suite.mockGroupService,
		map[providers.EntityCategory]sharing.ResourceType{providers.EntityCategoryApp: testAppSharingType})
	suite.ctx = context.Background()
}

// sharedWith answers how the role is shared with one organization unit.
func (suite *RoleSharingTestSuite) sharedWith(ouID string, overlay sharing.ResolvedOverlay) {
	suite.mockSharingService.EXPECT().ResolveOverlayRules(mock.Anything, RoleSharingType, "role1", ouID).
		Return(overlay, nil).Once()
}

// lockedKinds returns the rules of a reached organization unit with the given fields locked.
func lockedKinds(locked ...string) map[string]sharing.OverlayRule {
	rules := map[string]sharing.OverlayRule{
		sharingFieldAssignments: {Editable: true},
		sharingFieldUsers:       {Editable: true},
		sharingFieldApps:        {Editable: true},
		sharingFieldAgents:      {Editable: true},
		sharingFieldGroups:      {Editable: true},
	}
	for _, field := range locked {
		rules[field] = sharing.OverlayRule{Editable: false}
	}
	return rules
}

// Declaration

func (suite *RoleSharingTestSuite) TestDeclaration_NamesRolesAndTheirAssignmentFields() {
	decl := newRoleSharingDeclaration(suite.mockStore)

	suite.Equal(RoleSharingType, decl.ResourceType())

	fields := decl.Fields()
	suite.Require().Len(fields, 5)
	suite.Equal(sharingFieldAssignments, fields[0].Key)
	suite.Empty(fields[0].FallbackKey)
	for _, field := range fields {
		suite.Equal(sharing.FieldReferenceSet, field.Kind)
		suite.Require().NotNil(field.Default, "a field no rule names is answered from its own default")
		suite.True(field.Default.Editable)
	}
	for _, field := range fields[1:] {
		suite.Equal(sharingFieldAssignments, field.FallbackKey)
	}
}

func (suite *RoleSharingTestSuite) TestDeclaration_OwningOUID() {
	decl := newRoleSharingDeclaration(suite.mockStore)

	suite.mockStore.EXPECT().GetRole(mock.Anything, "role1").
		Return(RoleWithPermissions{ID: "role1", OUID: testOwnerOU}, nil).Once()
	ouID, svcErr := decl.OwningOUID(suite.ctx, "role1")
	suite.Nil(svcErr)
	suite.Equal(testOwnerOU, ouID)

	suite.mockStore.EXPECT().GetRole(mock.Anything, "missing").
		Return(RoleWithPermissions{}, ErrRoleNotFound).Once()
	_, svcErr = decl.OwningOUID(suite.ctx, "missing")
	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorRoleNotFound.Code, svcErr.Code)

	suite.mockStore.EXPECT().GetRole(mock.Anything, "broken").
		Return(RoleWithPermissions{}, errors.New("store down")).Once()
	_, svcErr = decl.OwningOUID(suite.ctx, "broken")
	suite.Require().NotNil(svcErr)
	suite.Equal(tidcommon.InternalServerError.Code, svcErr.Code)
}

// A rule on a role says whether a kind of assignee may hold it, so one that lists values is refused
// as a client error, which is what makes the framework refuse the policy.
func (suite *RoleSharingTestSuite) TestDeclaration_RefusesRuleValues() {
	decl := newRoleSharingDeclaration(suite.mockStore)

	svcErr := decl.ValidateMembers(suite.ctx, "role1", sharingFieldUsers, testOwnerOU, []string{"user1"})

	suite.Require().NotNil(svcErr)
	suite.Equal(tidcommon.ClientErrorType, svcErr.Type)
	suite.Equal(ErrorSharingRuleValuesNotSupported.Code, svcErr.Code)

	_, isMemberValidator := interface{}(decl).(sharing.MemberValidator)
	suite.True(isMemberValidator, "the framework finds the capability by type assertion")
}

// An organization unit that loses the role loses the assignments made in it, through the cleanup the
// framework runs.
func (suite *RoleSharingTestSuite) TestDeclaration_DeleteOverlayValuesRemovesTheUnitsAssignments() {
	decl := newRoleSharingDeclaration(suite.mockStore)
	_, isCleaner := interface{}(decl).(sharing.OverlayCleaner)
	suite.True(isCleaner, "the framework finds the capability by type assertion")

	suite.mockStore.EXPECT().DeleteAssignmentsByRoleAndOU(mock.Anything, "role1", "ou-child").Return(nil).Once()
	suite.NoError(decl.DeleteOverlayValues(suite.ctx, "role1", "ou-child"))

	suite.mockStore.EXPECT().DeleteAssignmentsByRoleAndOU(mock.Anything, "role1", "ou-broken").
		Return(errors.New("store down")).Once()
	suite.Error(decl.DeleteOverlayValues(suite.ctx, "role1", "ou-broken"))
}

// resolve

func (suite *RoleSharingTestSuite) TestResolve_DefaultsToTheAssigneesOwnOrganizationUnit() {
	suite.mockEntityService.EXPECT().GetEntitiesByIDs(mock.Anything, []string{"user1"}).
		Return([]providers.Entity{{ID: "user1", Category: providers.EntityCategoryUser, OUID: "ou-user"}}, nil)
	suite.mockGroupService.EXPECT().GetGroupsByIDs(mock.Anything, []string{"group1"}).
		Return(map[string]*group.Group{"group1": {ID: "group1", OUID: "ou-group"}}, nil)

	resolved, svcErr := suite.scope.resolve(suite.ctx, []RoleAssignment{
		{ID: "user1", Type: AssigneeTypeUser},
		{ID: "group1", Type: AssigneeTypeGroup},
	}, true)

	suite.Nil(svcErr)
	suite.Equal([]RoleAssignment{
		{ID: "user1", Type: AssigneeTypeUser, OUID: "ou-user"},
		{ID: "group1", Type: AssigneeTypeGroup, OUID: "ou-group"},
	}, resolved)
}

func (suite *RoleSharingTestSuite) TestResolve_AcceptsAnAssigneeSharedWithTheNamedOrganizationUnit() {
	suite.mockEntityService.EXPECT().GetEntitiesByIDs(mock.Anything, []string{"app1"}).
		Return([]providers.Entity{{ID: "app1", Category: providers.EntityCategoryApp, OUID: testOwnerOU}}, nil)
	suite.mockSharingService.EXPECT().IsVisible(mock.Anything, testAppSharingType, "app1", testShareeOU).
		Return(true, nil).Once()

	resolved, svcErr := suite.scope.resolve(suite.ctx,
		[]RoleAssignment{{ID: "app1", Type: AssigneeTypeApp, OUID: testShareeOU}}, true)

	suite.Nil(svcErr)
	suite.Equal(testShareeOU, resolved[0].OUID)
}

func (suite *RoleSharingTestSuite) TestResolve_RefusesAnOrganizationUnitTheAssigneeIsNotIn() {
	testCases := []struct {
		name       string
		assignment RoleAssignment
		setup      func()
	}{
		{
			name:       "an application that is not shared there",
			assignment: RoleAssignment{ID: "app1", Type: AssigneeTypeApp, OUID: testShareeOU},
			setup: func() {
				suite.mockEntityService.EXPECT().GetEntitiesByIDs(mock.Anything, []string{"app1"}).
					Return([]providers.Entity{{ID: "app1", Category: providers.EntityCategoryApp, OUID: testOwnerOU}},
						nil).Once()
				suite.mockSharingService.EXPECT().IsVisible(mock.Anything, testAppSharingType, "app1", testShareeOU).
					Return(false, nil).Once()
			},
		},
		{
			name:       "a user, which cannot be shared",
			assignment: RoleAssignment{ID: "user1", Type: AssigneeTypeUser, OUID: testShareeOU},
			setup: func() {
				suite.mockEntityService.EXPECT().GetEntitiesByIDs(mock.Anything, []string{"user1"}).
					Return([]providers.Entity{{ID: "user1", Category: providers.EntityCategoryUser, OUID: testOwnerOU}},
						nil).Once()
			},
		},
		{
			name:       "a group, which cannot be shared",
			assignment: RoleAssignment{ID: "group1", Type: AssigneeTypeGroup, OUID: testShareeOU},
			setup: func() {
				suite.mockGroupService.EXPECT().GetGroupsByIDs(mock.Anything, []string{"group1"}).
					Return(map[string]*group.Group{"group1": {ID: "group1", OUID: testOwnerOU}}, nil).Once()
			},
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			tc.setup()
			resolved, svcErr := suite.scope.resolve(suite.ctx, []RoleAssignment{tc.assignment}, true)
			suite.Nil(resolved)
			suite.Require().NotNil(svcErr)
			suite.Equal(ErrorAssigneeNotInOrganizationUnit.Code, svcErr.Code)
		})
	}
}

// Removing an assignment has to work after the assignee stopped being shared with the unit.
// An application assignment naming an organization unit that does not exist is refused as one the
// application is not shared with, not reported as a server failure.
func (suite *RoleSharingTestSuite) TestResolve_TreatsAnUnknownOrganizationUnitAsNotShared() {
	suite.mockEntityService.EXPECT().GetEntitiesByIDs(mock.Anything, []string{"app1"}).
		Return([]providers.Entity{{ID: "app1", Category: providers.EntityCategoryApp, OUID: testOwnerOU}}, nil).Once()
	suite.mockSharingService.EXPECT().IsVisible(mock.Anything, testAppSharingType, "app1", "no-such-ou").
		Return(false, &oupkg.ErrorOrganizationUnitNotFound).Once()

	_, svcErr := suite.scope.resolve(suite.ctx,
		[]RoleAssignment{{ID: "app1", Type: AssigneeTypeApp, OUID: "no-such-ou"}}, true)

	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorAssigneeNotInOrganizationUnit.Code, svcErr.Code)
}

func (suite *RoleSharingTestSuite) TestResolve_DoesNotAskForMembershipWhenRemoving() {
	suite.mockEntityService.EXPECT().GetEntitiesByIDs(mock.Anything, []string{"app1"}).
		Return([]providers.Entity{{ID: "app1", Category: providers.EntityCategoryApp, OUID: testOwnerOU}}, nil)

	resolved, svcErr := suite.scope.resolve(suite.ctx,
		[]RoleAssignment{{ID: "app1", Type: AssigneeTypeApp, OUID: testShareeOU}}, false)

	suite.Nil(svcErr)
	suite.Equal(testShareeOU, resolved[0].OUID)
}

func (suite *RoleSharingTestSuite) TestResolve_RefusesUnknownOrMistypedAssignees() {
	suite.Run("an entity that does not exist", func() {
		suite.mockEntityService.EXPECT().GetEntitiesByIDs(mock.Anything, []string{"ghost"}).
			Return([]providers.Entity{}, nil).Once()
		_, svcErr := suite.scope.resolve(suite.ctx, []RoleAssignment{{ID: "ghost", Type: AssigneeTypeUser}}, true)
		suite.Require().NotNil(svcErr)
		suite.Equal(ErrorInvalidAssignmentID.Code, svcErr.Code)
	})
	suite.Run("an entity given under another type", func() {
		suite.mockEntityService.EXPECT().GetEntitiesByIDs(mock.Anything, []string{"app1"}).
			Return([]providers.Entity{{ID: "app1", Category: providers.EntityCategoryApp}}, nil).Once()
		_, svcErr := suite.scope.resolve(suite.ctx, []RoleAssignment{{ID: "app1", Type: AssigneeTypeUser}}, true)
		suite.Require().NotNil(svcErr)
		suite.Equal(ErrorInvalidAssignmentID.Code, svcErr.Code)
	})
	suite.Run("one entity given under two types", func() {
		_, svcErr := suite.scope.resolve(suite.ctx, []RoleAssignment{
			{ID: "id1", Type: AssigneeTypeUser}, {ID: "id1", Type: AssigneeTypeApp},
		}, true)
		suite.Require().NotNil(svcErr)
		suite.Equal(ErrorInvalidAssignmentID.Code, svcErr.Code)
	})
	suite.Run("a group that does not exist", func() {
		suite.mockGroupService.EXPECT().GetGroupsByIDs(mock.Anything, []string{"ghost"}).
			Return(map[string]*group.Group{}, nil).Once()
		_, svcErr := suite.scope.resolve(suite.ctx, []RoleAssignment{{ID: "ghost", Type: AssigneeTypeGroup}}, true)
		suite.Require().NotNil(svcErr)
		suite.Equal(ErrorInvalidAssignmentID.Code, svcErr.Code)
	})
}

func (suite *RoleSharingTestSuite) TestResolve_ReportsLookupFailuresAsInternal() {
	suite.Run("entity lookup", func() {
		suite.mockEntityService.EXPECT().GetEntitiesByIDs(mock.Anything, []string{"user1"}).
			Return(nil, errors.New("store down")).Once()
		_, svcErr := suite.scope.resolve(suite.ctx, []RoleAssignment{{ID: "user1", Type: AssigneeTypeUser}}, true)
		suite.Require().NotNil(svcErr)
		suite.Equal(tidcommon.InternalServerError.Code, svcErr.Code)
	})
	suite.Run("group lookup", func() {
		suite.mockGroupService.EXPECT().GetGroupsByIDs(mock.Anything, []string{"group1"}).
			Return(nil, &tidcommon.InternalServerError).Once()
		_, svcErr := suite.scope.resolve(suite.ctx, []RoleAssignment{{ID: "group1", Type: AssigneeTypeGroup}}, true)
		suite.Require().NotNil(svcErr)
		suite.Equal(tidcommon.InternalServerError.Code, svcErr.Code)
	})
	suite.Run("sharing lookup", func() {
		suite.mockEntityService.EXPECT().GetEntitiesByIDs(mock.Anything, []string{"app1"}).
			Return([]providers.Entity{{ID: "app1", Category: providers.EntityCategoryApp, OUID: testOwnerOU}},
				nil).Once()
		suite.mockSharingService.EXPECT().IsVisible(mock.Anything, testAppSharingType, "app1", testShareeOU).
			Return(false, &tidcommon.InternalServerError).Once()
		_, svcErr := suite.scope.resolve(suite.ctx,
			[]RoleAssignment{{ID: "app1", Type: AssigneeTypeApp, OUID: testShareeOU}}, true)
		suite.Require().NotNil(svcErr)
		suite.Equal(tidcommon.InternalServerError.Code, svcErr.Code)
	})
}

// requireAssignable

func (suite *RoleSharingTestSuite) TestRequireAssignable_AllowsTheOwnerAndReachedOrganizationUnits() {
	suite.sharedWith(testOwnerOU, sharing.ResolvedOverlay{Owned: true, Visible: true})
	suite.sharedWith(testShareeOU, sharing.ResolvedOverlay{Visible: true, Rules: lockedKinds()})

	svcErr := suite.scope.requireAssignable(suite.ctx, "role1", []RoleAssignment{
		{ID: "user1", Type: AssigneeTypeUser, OUID: testOwnerOU},
		{ID: "user2", Type: AssigneeTypeUser, OUID: testShareeOU},
		{ID: "group1", Type: AssigneeTypeGroup, OUID: testShareeOU},
	})

	suite.Nil(svcErr)
}

// The owner is bounded by nothing it did not declare itself, so a kind it locked for the units it
// shares with is still its own to assign.
func (suite *RoleSharingTestSuite) TestRequireAssignable_DoesNotHoldTheOwnerToItsOwnTerms() {
	suite.sharedWith(testOwnerOU, sharing.ResolvedOverlay{
		Owned: true, Visible: true, Rules: lockedKinds(sharingFieldApps),
	})

	svcErr := suite.scope.requireAssignable(suite.ctx, "role1",
		[]RoleAssignment{{ID: "app1", Type: AssigneeTypeApp, OUID: testOwnerOU}})

	suite.Nil(svcErr)
}

func (suite *RoleSharingTestSuite) TestRequireAssignable_RefusesALockedKind() {
	for assigneeType, field := range sharingFieldByAssigneeType {
		suite.Run(string(assigneeType), func() {
			suite.sharedWith(testShareeOU, sharing.ResolvedOverlay{Visible: true, Rules: lockedKinds(field)})

			svcErr := suite.scope.requireAssignable(suite.ctx, "role1",
				[]RoleAssignment{{ID: "id1", Type: assigneeType, OUID: testShareeOU}})

			suite.Require().NotNil(svcErr)
			suite.Equal(ErrorAssigneeTypeNotAssignable.Code, svcErr.Code)
		})
	}
}

// A role is assignable only in its owner and the organization units a policy reaches. A role no
// policy names reaches none, so it is assignable in its owner alone.
func (suite *RoleSharingTestSuite) TestRequireAssignable_RefusesAnOrganizationUnitTheRoleDoesNotReach() {
	suite.sharedWith("ou-outside", sharing.ResolvedOverlay{})

	svcErr := suite.scope.requireAssignable(suite.ctx, "role1",
		[]RoleAssignment{{ID: "user1", Type: AssigneeTypeUser, OUID: "ou-outside"}})

	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorRoleNotAssignableInOrganizationUnit.Code, svcErr.Code)
}

func (suite *RoleSharingTestSuite) TestRequireAssignable_ReportsSharingFailuresAsInternal() {
	suite.mockSharingService.EXPECT().ResolveOverlayRules(mock.Anything, RoleSharingType, "role1", testShareeOU).
		Return(sharing.ResolvedOverlay{}, &tidcommon.InternalServerError).Once()

	svcErr := suite.scope.requireAssignable(suite.ctx, "role1",
		[]RoleAssignment{{ID: "user1", Type: AssigneeTypeUser, OUID: testShareeOU}})

	suite.Require().NotNil(svcErr)
	suite.Equal(tidcommon.InternalServerError.Code, svcErr.Code)
}
