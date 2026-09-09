// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"context"

	"github.com/thunder-id/thunderid/internal/sharing"
)

// Sharing-framework resource type identifiers for the three levels of the permission catalog.
// Modeling each level as its own resource type (rather than one "resource_server" type) is what
// lets a specific action be shared while a sibling is withheld — the sharing framework's grain of
// control is exactly "one resourceID of one resourceType", so matching that grain to each tree
// level reuses Share/Unshare/IsShared/ListGrants unchanged. See
const (
	resourceServerSharingType sharing.ResourceType = "resource_server"
	resourceNodeSharingType   sharing.ResourceType = "resource"
	actionSharingType         sharing.ResourceType = "action"
)

// nodeKindResource/nodeKindAction identify which table a node ID belongs to for
// ResolvePermissionNode/ResolveNodePermission and onNodeUnshared — a plain-string counterpart to
// resourceNodeSharingType/actionSharingType (sharing.ResourceType) for the store layer, which has
// no dependency on the sharing package.
const (
	nodeKindResource = "resource"
	nodeKindAction   = "action"
)

// None of the three declares a templated field: every field on a resource server, resource, or
// action defines the permission's global identity/meaning, not per-OU state layered on top of a
// shared, unchanging definition (unlike role's "assignments"). See

// resourceServerTypeDeclaration implements sharing.ResourceTypeDeclaration for resource servers.
// It does not implement SharingHooks: a resource server has no permission string of its own (see
// derivePermission), and unsharing it always cascades to revoke every descendant resource/action
// grant individually (see unshareResourceTree), so each descendant's own SharingHooks.OnUnshare
// fires for itself — there is nothing left for the resource-server level to clean up.
type resourceServerTypeDeclaration struct{}

func newResourceServerTypeDeclaration() sharing.ResourceTypeDeclaration {
	return &resourceServerTypeDeclaration{}
}

func (d *resourceServerTypeDeclaration) ResourceType() sharing.ResourceType {
	return resourceServerSharingType
}

func (d *resourceServerTypeDeclaration) TemplatedFields() []sharing.TemplatedFieldDeclaration {
	return nil
}

// resourceNodeTypeDeclaration implements sharing.ResourceTypeDeclaration and sharing.SharingHooks
// for resources.
type resourceNodeTypeDeclaration struct {
	service *resourceService
}

func newResourceNodeTypeDeclaration(service *resourceService) sharing.ResourceTypeDeclaration {
	return &resourceNodeTypeDeclaration{service: service}
}

func (d *resourceNodeTypeDeclaration) ResourceType() sharing.ResourceType {
	return resourceNodeSharingType
}

func (d *resourceNodeTypeDeclaration) TemplatedFields() []sharing.TemplatedFieldDeclaration {
	return nil
}

// OnUnshare implements sharing.SharingHooks. See resourceService.onNodeUnshared.
func (d *resourceNodeTypeDeclaration) OnUnshare(ctx context.Context, resourceID, ouID string) error {
	return d.service.onNodeUnshared(ctx, nodeKindResource, resourceID, ouID)
}

// actionTypeDeclaration implements sharing.ResourceTypeDeclaration and sharing.SharingHooks for
// actions.
type actionTypeDeclaration struct {
	service *resourceService
}

func newActionTypeDeclaration(service *resourceService) sharing.ResourceTypeDeclaration {
	return &actionTypeDeclaration{service: service}
}

func (d *actionTypeDeclaration) ResourceType() sharing.ResourceType {
	return actionSharingType
}

func (d *actionTypeDeclaration) TemplatedFields() []sharing.TemplatedFieldDeclaration {
	return nil
}

// OnUnshare implements sharing.SharingHooks. See resourceService.onNodeUnshared.
func (d *actionTypeDeclaration) OnUnshare(ctx context.Context, resourceID, ouID string) error {
	return d.service.onNodeUnshared(ctx, nodeKindAction, resourceID, ouID)
}
