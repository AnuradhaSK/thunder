// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/sharing"
)

// ResourceTypeDeclarationTestSuite tests role's onboarding onto the sharing framework.
type ResourceTypeDeclarationTestSuite struct {
	suite.Suite
	mockStore *roleStoreInterfaceMock
	decl      sharing.ResourceTypeDeclaration
}

func TestResourceTypeDeclarationTestSuite(t *testing.T) {
	suite.Run(t, new(ResourceTypeDeclarationTestSuite))
}

func (suite *ResourceTypeDeclarationTestSuite) SetupTest() {
	suite.mockStore = newRoleStoreInterfaceMock(suite.T())
	suite.decl = newRoleResourceTypeDeclaration(suite.mockStore)
}

func (suite *ResourceTypeDeclarationTestSuite) TestResourceType() {
	suite.Equal(roleSharingResourceType, suite.decl.ResourceType())
}

func (suite *ResourceTypeDeclarationTestSuite) TestTemplatedFields() {
	fields := suite.decl.TemplatedFields()

	suite.Require().Len(fields, 5)
	byKey := make(map[string]sharing.TemplatedFieldDeclaration, len(fields))
	for _, f := range fields {
		byKey[f.Key] = f
	}
	suite.Contains(byKey, roleTemplatedFieldAssignments)
	suite.Empty(byKey[roleTemplatedFieldAssignments].FallbackKey,
		"the blanket field has no coarser fallback of its own")

	for _, typedKey := range []string{
		roleTemplatedFieldAssignmentsUser, roleTemplatedFieldAssignmentsGroup,
		roleTemplatedFieldAssignmentsApp, roleTemplatedFieldAssignmentsAgent,
	} {
		suite.Require().Contains(byKey, typedKey)
		suite.Equal(roleTemplatedFieldAssignments, byKey[typedKey].FallbackKey,
			"each per-type field must fall back to the blanket field")
	}
}

func (suite *ResourceTypeDeclarationTestSuite) TestAssignmentsFieldKeyForType() {
	suite.Equal(roleTemplatedFieldAssignmentsUser, assignmentsFieldKeyForType(AssigneeTypeUser))
	suite.Equal(roleTemplatedFieldAssignmentsGroup, assignmentsFieldKeyForType(AssigneeTypeGroup))
	suite.Equal(roleTemplatedFieldAssignmentsApp, assignmentsFieldKeyForType(AssigneeTypeApp))
	suite.Equal(roleTemplatedFieldAssignmentsAgent, assignmentsFieldKeyForType(AssigneeTypeAgent))
	suite.Equal("", assignmentsFieldKeyForType(AssigneeType("unknown")))
}

func (suite *ResourceTypeDeclarationTestSuite) TestOnUnshare_DelegatesToStore() {
	hooks, ok := suite.decl.(sharing.SharingHooks)
	suite.Require().True(ok, "role's declaration must implement sharing.SharingHooks")

	suite.mockStore.On("DeleteAssignmentsByOUID", mock.Anything, "role1", "sharee-ou").Return(nil)

	err := hooks.OnUnshare(context.Background(), "role1", "sharee-ou")

	suite.NoError(err)
}

func (suite *ResourceTypeDeclarationTestSuite) TestOnUnshare_PropagatesStoreError() {
	hooks := suite.decl.(sharing.SharingHooks)
	suite.mockStore.On("DeleteAssignmentsByOUID", mock.Anything, "role1", "sharee-ou").
		Return(errors.New("delete failed"))

	err := hooks.OnUnshare(context.Background(), "role1", "sharee-ou")

	suite.Error(err)
}

func (suite *ResourceTypeDeclarationTestSuite) TestErrorResourceDeletionRestrictedToOwner() {
	provider, ok := suite.decl.(sharing.DeletionOwnershipError)
	suite.Require().True(ok, "role's declaration must implement sharing.DeletionOwnershipError")

	svcErr := provider.ErrorResourceDeletionRestrictedToOwner()

	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorRoleDeletionRestrictedToOwner.Code, svcErr.Code)
}
