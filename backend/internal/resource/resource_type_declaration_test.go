// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/thunder-id/thunderid/internal/sharing"
)

func TestResourceTypeDeclarations(t *testing.T) {
	testCases := []struct {
		name         string
		decl         sharing.ResourceTypeDeclaration
		expectedType sharing.ResourceType
	}{
		{"ResourceServer", newResourceServerTypeDeclaration(), resourceServerSharingType},
		{"ResourceNode", newResourceNodeTypeDeclaration(&resourceService{}), resourceNodeSharingType},
		{"Action", newActionTypeDeclaration(&resourceService{}), actionSharingType},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedType, tc.decl.ResourceType())
			assert.Nil(t, tc.decl.TemplatedFields())
		})
	}
}

func TestResourceTypeDeclarations_SharingHooks(t *testing.T) {
	// The resource server never implements SharingHooks: it has no permission string of its own to
	// clean up (see resource_type_declaration.go's doc comment).
	_, ok := newResourceServerTypeDeclaration().(sharing.SharingHooks)
	assert.False(t, ok)

	nodeDecl, ok := newResourceNodeTypeDeclaration(&resourceService{}).(sharing.SharingHooks)
	assert.True(t, ok, "resourceNodeTypeDeclaration must implement sharing.SharingHooks")

	actionDecl, ok := newActionTypeDeclaration(&resourceService{}).(sharing.SharingHooks)
	assert.True(t, ok, "actionTypeDeclaration must implement sharing.SharingHooks")

	// With no rolePermissionRevoker wired in, OnUnshare is a documented no-op rather than a panic
	// or error, matching resourceService.onNodeUnshared's nil-check.
	assert.NoError(t, nodeDecl.OnUnshare(context.Background(), "res-1", "ou-1"))
	assert.NoError(t, actionDecl.OnUnshare(context.Background(), "act-1", "ou-1"))
}
