// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"context"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"

	"github.com/thunder-id/thunderid/internal/sharing"
	"github.com/thunder-id/thunderid/internal/system/log"
)

// resourceTreeNode identifies one node (a resource or an action) in a resource server's tree, for
// cascade share/unshare enumeration.
type resourceTreeNode struct {
	id       string
	nodeType sharing.ResourceType
}

// RolePermissionRevoker is implemented by internal/role so that unsharing a resource/action can
// strip a now-invisible permission from every role owned by the OU that just lost access to it,
// without internal/resource importing internal/role (which already imports internal/resource for
// permission validation/visibility — importing it back here would cycle). Wired in by
// servicemanager, after both packages are initialized, via SetRolePermissionRevoker. See
type RolePermissionRevoker interface {
	// RevokeRolePermissionForOU deletes permission (scoped to resourceServerID) from every role
	// owned by ouID that currently has it, returning the number of roles it was removed from.
	RevokeRolePermissionForOU(ctx context.Context, ouID, resourceServerID, permission string) (int, error)
}

// onNodeUnshared implements sharing.SharingHooks.OnUnshare for resource and action nodes (see
// resourceNodeTypeDeclaration/actionTypeDeclaration in resource_type_declaration.go): when ouID
// loses access to nodeID, the specific permission string nodeID derives is stripped from every
// role owned by ouID that names it. Cascade unshare (unshareResourceTree, above) already calls
// Unshare individually for every descendant resource/action sharing the same OU selection, so this
// only ever needs to handle nodeID's own permission string, never its descendants' — each
// descendant's own Unshare call fires this same hook for itself. See §5.4 of the design doc.
func (rs *resourceService) onNodeUnshared(ctx context.Context, kind, nodeID, ouID string) error {
	if rs.rolePermissionRevoker == nil {
		return nil
	}
	resourceServerID, permission, found, err := rs.resourceStore.ResolveNodePermission(ctx, kind, nodeID)
	if err != nil {
		rs.logger.Error(ctx, "Failed to resolve node permission for role-permission cleanup",
			log.String("kind", kind), log.String("nodeID", nodeID), log.Error(err))
		return err
	}
	if !found {
		return nil
	}
	if _, err := rs.rolePermissionRevoker.RevokeRolePermissionForOU(
		ctx, ouID, resourceServerID, permission,
	); err != nil {
		rs.logger.Error(ctx, "Failed to revoke role permission after unshare",
			log.String("ouID", ouID), log.String("resourceServerId", resourceServerID),
			log.String("permission", permission), log.Error(err))
		return err
	}
	return nil
}

// appendPermissionsHiddenFromOU is the organization-unit half of ValidatePermissions (§4.4): it
// adds to invalid every permission that exists on the resource server but that ouID cannot see.
// permissions holds the candidates already checked for existence, invalid the ones that failed that
// check. The deployment root permission never reaches here; ValidatePermissions holds it back.
func (rs *resourceService) appendPermissionsHiddenFromOU(
	ctx context.Context, resourceServer providers.ResourceServer, permissions, invalid []string, ouID string,
) ([]string, *tidcommon.ServiceError) {
	// The organization unit that owns the resource server sees everything beneath it.
	if resourceServer.OUID == ouID {
		return invalid, nil
	}

	invalidSet := make(map[string]struct{}, len(invalid))
	for _, permission := range invalid {
		invalidSet[permission] = struct{}{}
	}

	// Nothing under a resource server that was never granted to the organization unit is visible.
	shared, svcErr := rs.sharingService.IsShared(ctx, resourceServerSharingType, resourceServer.ID, ouID)
	if svcErr != nil {
		return nil, svcErr
	}
	if !shared {
		for _, permission := range permissions {
			if _, already := invalidSet[permission]; !already {
				invalid = append(invalid, permission)
			}
		}
		return invalid, nil
	}

	// The resource server is granted, so each permission's own node has to be granted as well.
	for _, permission := range permissions {
		if _, already := invalidSet[permission]; already {
			continue
		}
		nodeID, kind, found, err := rs.resourceStore.ResolvePermissionNode(ctx, resourceServer.ID, permission)
		if err != nil {
			rs.logger.Error(ctx, "Failed to resolve permission node",
				log.String("resourceServerId", resourceServer.ID),
				log.String("permission", permission), log.Error(err))
			return nil, &tidcommon.InternalServerError
		}
		if !found {
			invalid = append(invalid, permission)
			continue
		}
		nodeType := resourceNodeSharingType
		if kind == nodeKindAction {
			nodeType = actionSharingType
		}
		nodeShared, svcErr := rs.sharingService.IsShared(ctx, nodeType, nodeID, ouID)
		if svcErr != nil {
			return nil, svcErr
		}
		if !nodeShared {
			invalid = append(invalid, permission)
		}
	}

	return invalid, nil
}

// inheritGrants replays every grant recorded for (parentType, parentID) onto
// (childType, childID), so a newly created resource/action under an already-shared parent becomes
// visible without a separate manual share call. See §5.2 of the design doc. owningOUID is the
// resource server's own OU, the only coherent owner for any node beneath it.
func (rs *resourceService) inheritGrants(
	ctx context.Context, parentType sharing.ResourceType, parentID string,
	childType sharing.ResourceType, childID, owningOUID string,
) *tidcommon.ServiceError {
	grants, svcErr := rs.sharingService.ExportGrants(ctx, parentType, parentID)
	if svcErr != nil {
		return svcErr
	}
	for _, g := range grants {
		if _, svcErr := rs.sharingService.Share(
			ctx, childType, childID, owningOUID, g.ActingOUID, g.Policy,
		); svcErr != nil {
			return svcErr
		}
	}
	return nil
}

// shareResourceTree shares (nodeType, nodeID) per req and, when cascade is true, every descendant
// resource/action currently beneath it (minus req.ExcludedNodeIDs). See §5.1 of the design doc.
func (rs *resourceService) shareResourceTree(
	ctx context.Context, resourceServerID string, resourceServer providers.ResourceServer,
	nodeType sharing.ResourceType, nodeID string, req ShareRequest, cascade bool,
) ([]GrantInfo, *tidcommon.ServiceError) {
	owningOUID := resourceServer.OUID
	actingOUID := req.OUID
	if actingOUID == "" {
		actingOUID = owningOUID
	}
	policy := req.ToSharePolicy()

	grants, svcErr := rs.sharingService.Share(ctx, nodeType, nodeID, owningOUID, actingOUID, policy)
	if svcErr != nil {
		return nil, svcErr
	}
	result := grantsToInfo(nodeType, nodeID, grants)

	if !cascade {
		return result, nil
	}

	descendants, svcErr := rs.descendantsOf(ctx, resourceServerID, nodeType, nodeID)
	if svcErr != nil {
		return nil, svcErr
	}
	excluded, svcErr := rs.expandExcludedNodes(ctx, resourceServerID, req.ExcludedNodeIDs)
	if svcErr != nil {
		return nil, svcErr
	}
	for _, d := range descendants {
		if _, skip := excluded[d.id]; skip {
			continue
		}
		dGrants, svcErr := rs.sharingService.Share(ctx, d.nodeType, d.id, owningOUID, actingOUID, policy)
		if svcErr != nil {
			return nil, svcErr
		}
		result = append(result, grantsToInfo(d.nodeType, d.id, dGrants)...)
	}

	return result, nil
}

// expandExcludedNodes turns the caller's excluded node ids into the full set of nodes to withhold,
// by adding every descendant of each excluded node.
//
// Excluding a node has to exclude its subtree, because visibility is resolved per node: a
// permission names an action, and ValidatePermissions looks that action up directly. Withholding
// a resource while still granting the actions beneath it would leave every one of its permissions
// visible, which is the opposite of what excluding it asked for. Actions are leaves, so only
// excluded resources expand.
func (rs *resourceService) expandExcludedNodes(
	ctx context.Context, resourceServerID string, excludedNodeIDs []string,
) (map[string]struct{}, *tidcommon.ServiceError) {
	excluded := make(map[string]struct{}, len(excludedNodeIDs))
	for _, id := range excludedNodeIDs {
		excluded[id] = struct{}{}
	}
	for _, id := range excludedNodeIDs {
		descendants, svcErr := rs.descendantsOf(ctx, resourceServerID, resourceNodeSharingType, id)
		if svcErr != nil {
			return nil, svcErr
		}
		for _, d := range descendants {
			excluded[d.id] = struct{}{}
		}
	}
	return excluded, nil
}

// unshareResourceTree revokes grantID (recorded against (nodeType, nodeID)) and, when cascade is
// true, every descendant grant created alongside it by the same original cascade share. See §5.3
// of the design doc for the exact matching rule.
func (rs *resourceService) unshareResourceTree(
	ctx context.Context, resourceServerID string, nodeType sharing.ResourceType, nodeID, grantID string,
	cascade bool,
) *tidcommon.ServiceError {
	grants, svcErr := rs.sharingService.ListGrants(ctx, nodeType, nodeID)
	if svcErr != nil {
		return svcErr
	}
	var target *sharing.Grant
	for i := range grants {
		if grants[i].ID == grantID {
			target = &grants[i]
			break
		}
	}
	if target == nil {
		return &sharing.ErrorGrantNotFound
	}

	if svcErr := rs.sharingService.Unshare(ctx, grantID); svcErr != nil {
		return svcErr
	}

	if !cascade {
		return nil
	}

	descendants, svcErr := rs.descendantsOf(ctx, resourceServerID, nodeType, nodeID)
	if svcErr != nil {
		return svcErr
	}
	for _, d := range descendants {
		dGrants, svcErr := rs.sharingService.ListGrants(ctx, d.nodeType, d.id)
		if svcErr != nil {
			return svcErr
		}
		for _, g := range dGrants {
			if sameOUSelection(g, *target) {
				if svcErr := rs.sharingService.Unshare(ctx, g.ID); svcErr != nil {
					return svcErr
				}
			}
		}
	}

	return nil
}

// descendantsOf returns every resource/action beneath anchorID, as a flat list: every resource
// (recursively) and action in the whole server when anchorType is resourceServerSharingType, or
// every sub-resource/action in anchorID's own subtree (anchorID's own actions included) when
// anchorType is resourceNodeSharingType.
func (rs *resourceService) descendantsOf(
	ctx context.Context, resourceServerID string, anchorType sharing.ResourceType, anchorID string,
) ([]resourceTreeNode, *tidcommon.ServiceError) {
	allResources, svcErr := rs.GetAllResourceList(ctx, resourceServerID)
	if svcErr != nil {
		return nil, svcErr
	}

	var nodes []resourceTreeNode
	var resourceScope []string

	if anchorType == resourceServerSharingType {
		for _, r := range allResources {
			nodes = append(nodes, resourceTreeNode{id: r.ID, nodeType: resourceNodeSharingType})
			resourceScope = append(resourceScope, r.ID)
		}
		topActions, svcErr := rs.allActionsUnder(ctx, resourceServerID, nil)
		if svcErr != nil {
			return nil, svcErr
		}
		for _, a := range topActions {
			nodes = append(nodes, resourceTreeNode{id: a.ID, nodeType: actionSharingType})
		}
	} else {
		childrenOf := make(map[string][]providers.Resource, len(allResources))
		for _, r := range allResources {
			if r.Parent != nil {
				childrenOf[*r.Parent] = append(childrenOf[*r.Parent], r)
			}
		}
		var walk func(parentID string)
		walk = func(parentID string) {
			for _, child := range childrenOf[parentID] {
				nodes = append(nodes, resourceTreeNode{id: child.ID, nodeType: resourceNodeSharingType})
				resourceScope = append(resourceScope, child.ID)
				walk(child.ID)
			}
		}
		walk(anchorID)
		resourceScope = append(resourceScope, anchorID)
	}

	for _, resID := range resourceScope {
		id := resID
		actions, svcErr := rs.allActionsUnder(ctx, resourceServerID, &id)
		if svcErr != nil {
			return nil, svcErr
		}
		for _, a := range actions {
			nodes = append(nodes, resourceTreeNode{id: a.ID, nodeType: actionSharingType})
		}
	}

	return nodes, nil
}

// allActionsUnder returns every action attached to resourceID (nil for resource-server-level
// actions), unfiltered by kind.
func (rs *resourceService) allActionsUnder(
	ctx context.Context, resourceServerID string, resourceID *string,
) ([]providers.Action, *tidcommon.ServiceError) {
	count, err := rs.resourceStore.GetActionListCount(ctx, resourceServerID, resourceID, "")
	if err != nil {
		rs.logger.Error(ctx, "Failed to get action count for cascade enumeration", log.Error(err))
		return nil, &tidcommon.InternalServerError
	}
	if count == 0 {
		return []providers.Action{}, nil
	}
	actions, err := rs.resourceStore.GetActionList(ctx, resourceServerID, resourceID, "", count, 0)
	if err != nil {
		rs.logger.Error(ctx, "Failed to list actions for cascade enumeration", log.Error(err))
		return nil, &tidcommon.InternalServerError
	}
	return actions, nil
}

// sameOUSelection reports whether a and b target the identical OU selection — same TargetScope,
// same TargetOUID (which, for TargetScopeAllChildren, holds the acting/anchor OU, not a literal
// target), and, for the two blanket scopes, the same ExcludedOUIDs set. Two grants targeting the
// same OU selection are considered part of the same cascade share operation (§5.3).
func sameOUSelection(a, b sharing.Grant) bool {
	if a.TargetScope != b.TargetScope || a.TargetOUID != b.TargetOUID {
		return false
	}
	switch a.TargetScope {
	case sharing.TargetScopeAllRoots, sharing.TargetScopeAllChildren:
		return sameStringSet(a.ExcludedOUIDs, b.ExcludedOUIDs)
	default:
		return true
	}
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, v := range a {
		set[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := set[v]; !ok {
			return false
		}
	}
	return true
}

// grantsToInfo converts sharing.Grant results for one specific node into the service-layer
// response shape, tagging each with the node that was actually shared.
func grantsToInfo(nodeType sharing.ResourceType, nodeID string, grants []sharing.Grant) []GrantInfo {
	result := make([]GrantInfo, len(grants))
	for i, g := range grants {
		result[i] = GrantInfo{
			ID:            g.ID,
			NodeType:      string(nodeType),
			NodeID:        nodeID,
			Stage:         string(g.Stage),
			TargetScope:   string(g.TargetScope),
			TargetOUID:    g.TargetOUID,
			OwningOUID:    g.OwningOUID,
			ExcludedOUIDs: g.ExcludedOUIDs,
		}
	}
	return result
}

// ShareResourceServer implements ResourceServiceInterface.
func (rs *resourceService) ShareResourceServer(
	ctx context.Context, id string, req ShareRequest,
) ([]GrantInfo, *tidcommon.ServiceError) {
	resourceServer, svcErr := rs.validateAndGetResourceServer(ctx, id)
	if svcErr != nil {
		return nil, svcErr
	}
	if svcErr := rs.RequireVisibility(ctx, resourceServerSharingType, id, resourceServer.OUID); svcErr != nil {
		return nil, svcErr
	}
	return rs.shareResourceTree(ctx, id, resourceServer, resourceServerSharingType, id, req, true)
}

// ListResourceServerGrants implements ResourceServiceInterface.
func (rs *resourceService) ListResourceServerGrants(
	ctx context.Context, id string,
) ([]GrantInfo, *tidcommon.ServiceError) {
	resourceServer, svcErr := rs.validateAndGetResourceServer(ctx, id)
	if svcErr != nil {
		return nil, svcErr
	}
	if svcErr := rs.RequireVisibility(ctx, resourceServerSharingType, id, resourceServer.OUID); svcErr != nil {
		return nil, svcErr
	}
	grants, svcErr := rs.sharingService.ListGrants(ctx, resourceServerSharingType, id)
	if svcErr != nil {
		return nil, svcErr
	}
	return grantsToInfo(resourceServerSharingType, id, grants), nil
}

// UnshareResourceServerGrant implements ResourceServiceInterface.
func (rs *resourceService) UnshareResourceServerGrant(ctx context.Context, id, grantID string) *tidcommon.ServiceError {
	resourceServer, svcErr := rs.validateAndGetResourceServer(ctx, id)
	if svcErr != nil {
		return svcErr
	}
	if svcErr := rs.RequireVisibility(ctx, resourceServerSharingType, id, resourceServer.OUID); svcErr != nil {
		return svcErr
	}
	return rs.unshareResourceTree(ctx, id, resourceServerSharingType, id, grantID, true)
}

// ShareResource implements ResourceServiceInterface.
func (rs *resourceService) ShareResource(
	ctx context.Context, resourceServerID, id string, req ShareRequest,
) ([]GrantInfo, *tidcommon.ServiceError) {
	resourceServer, svcErr := rs.validateAndGetResourceServer(ctx, resourceServerID)
	if svcErr != nil {
		return nil, svcErr
	}
	if _, svcErr := rs.validateAndGetResourceByID(ctx, id, resourceServerID); svcErr != nil {
		return nil, svcErr
	}
	if svcErr := rs.RequireVisibility(ctx, resourceNodeSharingType, id, resourceServer.OUID); svcErr != nil {
		return nil, svcErr
	}
	return rs.shareResourceTree(ctx, resourceServerID, resourceServer, resourceNodeSharingType, id, req, true)
}

// ListResourceGrants implements ResourceServiceInterface.
func (rs *resourceService) ListResourceGrants(
	ctx context.Context, resourceServerID, id string,
) ([]GrantInfo, *tidcommon.ServiceError) {
	resourceServer, svcErr := rs.validateAndGetResourceServer(ctx, resourceServerID)
	if svcErr != nil {
		return nil, svcErr
	}
	if _, svcErr := rs.validateAndGetResourceByID(ctx, id, resourceServerID); svcErr != nil {
		return nil, svcErr
	}
	if svcErr := rs.RequireVisibility(ctx, resourceNodeSharingType, id, resourceServer.OUID); svcErr != nil {
		return nil, svcErr
	}
	grants, svcErr := rs.sharingService.ListGrants(ctx, resourceNodeSharingType, id)
	if svcErr != nil {
		return nil, svcErr
	}
	return grantsToInfo(resourceNodeSharingType, id, grants), nil
}

// UnshareResourceGrant implements ResourceServiceInterface.
func (rs *resourceService) UnshareResourceGrant(
	ctx context.Context, resourceServerID, id, grantID string,
) *tidcommon.ServiceError {
	resourceServer, svcErr := rs.validateAndGetResourceServer(ctx, resourceServerID)
	if svcErr != nil {
		return svcErr
	}
	if _, svcErr := rs.validateAndGetResourceByID(ctx, id, resourceServerID); svcErr != nil {
		return svcErr
	}
	if svcErr := rs.RequireVisibility(ctx, resourceNodeSharingType, id, resourceServer.OUID); svcErr != nil {
		return svcErr
	}
	return rs.unshareResourceTree(ctx, resourceServerID, resourceNodeSharingType, id, grantID, true)
}

// ShareAction implements ResourceServiceInterface.
func (rs *resourceService) ShareAction(
	ctx context.Context, resourceServerID string, resourceID *string, id string, req ShareRequest,
) ([]GrantInfo, *tidcommon.ServiceError) {
	resourceServer, svcErr := rs.validateAndGetResourceServer(ctx, resourceServerID)
	if svcErr != nil {
		return nil, svcErr
	}
	if resourceID != nil {
		if _, svcErr := rs.validateAndGetResourceByID(ctx, *resourceID, resourceServerID); svcErr != nil {
			return nil, svcErr
		}
	}
	if svcErr := rs.RequireVisibility(ctx, actionSharingType, id, resourceServer.OUID); svcErr != nil {
		return nil, svcErr
	}
	// Actions are leaves — no cascade.
	return rs.shareResourceTree(ctx, resourceServerID, resourceServer, actionSharingType, id, req, false)
}

// ListActionGrants implements ResourceServiceInterface.
func (rs *resourceService) ListActionGrants(
	ctx context.Context, resourceServerID string, resourceID *string, id string,
) ([]GrantInfo, *tidcommon.ServiceError) {
	resourceServer, svcErr := rs.validateAndGetResourceServer(ctx, resourceServerID)
	if svcErr != nil {
		return nil, svcErr
	}
	if resourceID != nil {
		if _, svcErr := rs.validateAndGetResourceByID(ctx, *resourceID, resourceServerID); svcErr != nil {
			return nil, svcErr
		}
	}
	if svcErr := rs.RequireVisibility(ctx, actionSharingType, id, resourceServer.OUID); svcErr != nil {
		return nil, svcErr
	}
	grants, svcErr := rs.sharingService.ListGrants(ctx, actionSharingType, id)
	if svcErr != nil {
		return nil, svcErr
	}
	return grantsToInfo(actionSharingType, id, grants), nil
}

// UnshareActionGrant implements ResourceServiceInterface.
func (rs *resourceService) UnshareActionGrant(
	ctx context.Context, resourceServerID string, resourceID *string, id, grantID string,
) *tidcommon.ServiceError {
	resourceServer, svcErr := rs.validateAndGetResourceServer(ctx, resourceServerID)
	if svcErr != nil {
		return svcErr
	}
	if resourceID != nil {
		if _, svcErr := rs.validateAndGetResourceByID(ctx, *resourceID, resourceServerID); svcErr != nil {
			return svcErr
		}
	}
	if svcErr := rs.RequireVisibility(ctx, actionSharingType, id, resourceServer.OUID); svcErr != nil {
		return svcErr
	}
	return rs.unshareResourceTree(ctx, resourceServerID, actionSharingType, id, grantID, false)
}
