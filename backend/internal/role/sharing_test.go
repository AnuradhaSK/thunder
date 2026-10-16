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

	"github.com/thunder-id/thunderid/internal/sharing"
	"github.com/thunder-id/thunderid/tests/mocks/sharingmock"
)

const (
	testOwnerOU  = "ou-owner"
	testShareeOU = "ou-sharee"
)

type RoleSharingTestSuite struct {
	suite.Suite
	mockStore          *roleStoreInterfaceMock
	mockSharingService *sharingmock.SharingServiceInterfaceMock
	ctx                context.Context
}

func TestRoleSharingTestSuite(t *testing.T) {
	suite.Run(t, new(RoleSharingTestSuite))
}

func (suite *RoleSharingTestSuite) SetupTest() {
	suite.mockStore = newRoleStoreInterfaceMock(suite.T())
	suite.mockSharingService = sharingmock.NewSharingServiceInterfaceMock(suite.T())
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

// requireAssignable

func (suite *RoleSharingTestSuite) TestRequireAssignable_AllowsTheOwnerAndReachedOrganizationUnits() {
	suite.sharedWith(testOwnerOU, sharing.ResolvedOverlay{Owned: true, Visible: true})
	suite.sharedWith(testShareeOU, sharing.ResolvedOverlay{Visible: true, Rules: lockedKinds()})

	svcErr := requireAssignable(suite.ctx, suite.mockSharingService, "role1", []RoleAssignment{
		{ID: "user1", Type: AssigneeTypeUser, OUID: testOwnerOU},
		{ID: "user2", Type: AssigneeTypeUser, OUID: testShareeOU},
		{ID: "group1", Type: AssigneeTypeGroup, OUID: testShareeOU},
	}, assignmentLoggerComponentName)

	suite.Nil(svcErr)
}

// The owner is bounded by nothing it did not declare itself, so a kind it locked for the units it
// shares with is still its own to assign.
func (suite *RoleSharingTestSuite) TestRequireAssignable_DoesNotHoldTheOwnerToItsOwnTerms() {
	suite.sharedWith(testOwnerOU, sharing.ResolvedOverlay{
		Owned: true, Visible: true, Rules: lockedKinds(sharingFieldApps),
	})

	svcErr := requireAssignable(suite.ctx, suite.mockSharingService, "role1",
		[]RoleAssignment{{ID: "app1", Type: AssigneeTypeApp, OUID: testOwnerOU}}, assignmentLoggerComponentName)

	suite.Nil(svcErr)
}

func (suite *RoleSharingTestSuite) TestRequireAssignable_RefusesALockedKind() {
	for assigneeType, field := range sharingFieldByAssigneeType {
		suite.Run(string(assigneeType), func() {
			suite.sharedWith(testShareeOU, sharing.ResolvedOverlay{Visible: true, Rules: lockedKinds(field)})

			svcErr := requireAssignable(suite.ctx, suite.mockSharingService, "role1",
				[]RoleAssignment{{ID: "id1", Type: assigneeType, OUID: testShareeOU}}, assignmentLoggerComponentName)

			suite.Require().NotNil(svcErr)
			suite.Equal(ErrorAssigneeTypeNotAssignable.Code, svcErr.Code)
		})
	}
}

// A role is assignable only in its owner and the organization units a policy reaches. A role no
// policy names reaches none, so it is assignable in its owner alone.
func (suite *RoleSharingTestSuite) TestRequireAssignable_RefusesAnOrganizationUnitTheRoleDoesNotReach() {
	suite.sharedWith("ou-outside", sharing.ResolvedOverlay{})

	svcErr := requireAssignable(suite.ctx, suite.mockSharingService, "role1",
		[]RoleAssignment{{ID: "user1", Type: AssigneeTypeUser, OUID: "ou-outside"}}, assignmentLoggerComponentName)

	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorRoleNotAssignableInOrganizationUnit.Code, svcErr.Code)
}

func (suite *RoleSharingTestSuite) TestRequireAssignable_ReportsSharingFailuresAsInternal() {
	suite.mockSharingService.EXPECT().ResolveOverlayRules(mock.Anything, RoleSharingType, "role1", testShareeOU).
		Return(sharing.ResolvedOverlay{}, &tidcommon.InternalServerError).Once()

	svcErr := requireAssignable(suite.ctx, suite.mockSharingService, "role1",
		[]RoleAssignment{{ID: "user1", Type: AssigneeTypeUser, OUID: testShareeOU}}, assignmentLoggerComponentName)

	suite.Require().NotNil(svcErr)
	suite.Equal(tidcommon.InternalServerError.Code, svcErr.Code)
}
