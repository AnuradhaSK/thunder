// Copyright 2025 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"context"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"

	"github.com/thunder-id/thunderid/internal/sharing"
)

// fakeSharingService is a light-weight test double for sharing.ServiceInterface, mirroring the
// one in internal/role/service_test.go. Any call not stubbed via the corresponding func field
// fails loudly rather than silently returning a zero value.
type fakeSharingService struct {
	isSharedFunc func(
		ctx context.Context, resourceType sharing.ResourceType, resourceID, ouID string,
	) (bool, *tidcommon.ServiceError)
	resolveEditabilityFunc func(
		ctx context.Context, resourceType sharing.ResourceType, resourceID, owningOUID, ouID, fieldKey string,
	) (bool, *tidcommon.ServiceError)
	resolveEditableFieldsFunc func(
		ctx context.Context, resourceType sharing.ResourceType, resourceID, owningOUID, ouID string,
	) ([]string, *tidcommon.ServiceError)
	listSharedResourceIDsFunc func(
		ctx context.Context, resourceType sharing.ResourceType, ouID string,
	) ([]string, *tidcommon.ServiceError)
	shareFunc func(
		ctx context.Context, resourceType sharing.ResourceType, resourceID, owningOUID, actingOUID string,
		policy sharing.SharePolicy,
	) ([]sharing.Grant, *tidcommon.ServiceError)
	shareDeclarativeFunc func(
		ctx context.Context, resourceType sharing.ResourceType, resourceID, owningOUID, actingOUID string,
		policy sharing.SharePolicy,
	) ([]sharing.Grant, *tidcommon.ServiceError)
	unshareFunc    func(ctx context.Context, grantID string) *tidcommon.ServiceError
	listGrantsFunc func(
		ctx context.Context, resourceType sharing.ResourceType, resourceID string,
	) ([]sharing.Grant, *tidcommon.ServiceError)
	listGrantsPageFunc func(
		ctx context.Context, resourceType sharing.ResourceType, resourceID string, limit, offset int,
	) (*sharing.GrantPage, *tidcommon.ServiceError)
	exportGrantsFunc func(
		ctx context.Context, resourceType sharing.ResourceType, resourceID string,
	) ([]sharing.ReplayableGrant, *tidcommon.ServiceError)
	requireOwnershipFunc func(
		ctx context.Context, resourceType sharing.ResourceType, owningOUID string,
	) *tidcommon.ServiceError
	requireOwnershipForDeletionFunc func(
		ctx context.Context, resourceType sharing.ResourceType, owningOUID string,
	) *tidcommon.ServiceError
}

// RegisterResourceType is a no-op: Initialize always calls this three times during wiring to
// onboard resource servers, resources, and actions onto the sharing framework, so unlike the
// other methods here it's an expected call in every test that exercises Initialize, not just
// tests specifically targeting sharing behavior.
func (f *fakeSharingService) RegisterResourceType(_ sharing.ResourceTypeDeclaration) {}

func (f *fakeSharingService) Share(
	ctx context.Context, resourceType sharing.ResourceType, resourceID, owningOUID, actingOUID string,
	policy sharing.SharePolicy,
) ([]sharing.Grant, *tidcommon.ServiceError) {
	if f.shareFunc != nil {
		return f.shareFunc(ctx, resourceType, resourceID, owningOUID, actingOUID, policy)
	}
	panic("fakeSharingService: unexpected call to Share")
}

func (f *fakeSharingService) ShareDeclarative(
	ctx context.Context, resourceType sharing.ResourceType, resourceID, owningOUID, actingOUID string,
	policy sharing.SharePolicy,
) ([]sharing.Grant, *tidcommon.ServiceError) {
	if f.shareDeclarativeFunc != nil {
		return f.shareDeclarativeFunc(ctx, resourceType, resourceID, owningOUID, actingOUID, policy)
	}
	panic("fakeSharingService: unexpected call to ShareDeclarative")
}

func (f *fakeSharingService) Unshare(ctx context.Context, grantID string) *tidcommon.ServiceError {
	if f.unshareFunc != nil {
		return f.unshareFunc(ctx, grantID)
	}
	panic("fakeSharingService: unexpected call to Unshare")
}

func (f *fakeSharingService) ListGrants(
	ctx context.Context, resourceType sharing.ResourceType, resourceID string,
) ([]sharing.Grant, *tidcommon.ServiceError) {
	if f.listGrantsFunc != nil {
		return f.listGrantsFunc(ctx, resourceType, resourceID)
	}
	panic("fakeSharingService: unexpected call to ListGrants")
}

func (f *fakeSharingService) ListGrantsPage(
	ctx context.Context, resourceType sharing.ResourceType, resourceID string, limit, offset int,
) (*sharing.GrantPage, *tidcommon.ServiceError) {
	if f.listGrantsPageFunc != nil {
		return f.listGrantsPageFunc(ctx, resourceType, resourceID, limit, offset)
	}
	panic("fakeSharingService: unexpected call to ListGrantsPage")
}

func (f *fakeSharingService) ExportGrants(
	ctx context.Context, resourceType sharing.ResourceType, resourceID string,
) ([]sharing.ReplayableGrant, *tidcommon.ServiceError) {
	if f.exportGrantsFunc != nil {
		return f.exportGrantsFunc(ctx, resourceType, resourceID)
	}
	panic("fakeSharingService: unexpected call to ExportGrants")
}

func (f *fakeSharingService) IsShared(
	ctx context.Context, resourceType sharing.ResourceType, resourceID, ouID string,
) (bool, *tidcommon.ServiceError) {
	if f.isSharedFunc != nil {
		return f.isSharedFunc(ctx, resourceType, resourceID, ouID)
	}
	panic("fakeSharingService: unexpected call to IsShared")
}

func (f *fakeSharingService) ListSharedResourceIDs(
	ctx context.Context, resourceType sharing.ResourceType, ouID string,
) ([]string, *tidcommon.ServiceError) {
	if f.listSharedResourceIDsFunc != nil {
		return f.listSharedResourceIDsFunc(ctx, resourceType, ouID)
	}
	panic("fakeSharingService: unexpected call to ListSharedResourceIDs")
}

func (f *fakeSharingService) ResolveEditability(
	ctx context.Context, resourceType sharing.ResourceType, resourceID, owningOUID, ouID, fieldKey string,
) (bool, *tidcommon.ServiceError) {
	if f.resolveEditabilityFunc != nil {
		return f.resolveEditabilityFunc(ctx, resourceType, resourceID, owningOUID, ouID, fieldKey)
	}
	panic("fakeSharingService: unexpected call to ResolveEditability")
}

func (f *fakeSharingService) RequireOwnership(
	ctx context.Context, resourceType sharing.ResourceType, owningOUID string,
) *tidcommon.ServiceError {
	if f.requireOwnershipFunc != nil {
		return f.requireOwnershipFunc(ctx, resourceType, owningOUID)
	}
	panic("fakeSharingService: unexpected call to RequireOwnership")
}

func (f *fakeSharingService) RequireOwnershipForDeletion(
	ctx context.Context, resourceType sharing.ResourceType, owningOUID string,
) *tidcommon.ServiceError {
	if f.requireOwnershipForDeletionFunc != nil {
		return f.requireOwnershipForDeletionFunc(ctx, resourceType, owningOUID)
	}
	panic("fakeSharingService: unexpected call to RequireOwnershipForDeletion")
}

func (f *fakeSharingService) ResolveEditableFields(
	ctx context.Context, resourceType sharing.ResourceType, resourceID, owningOUID, ouID string,
) ([]string, *tidcommon.ServiceError) {
	if f.resolveEditableFieldsFunc != nil {
		return f.resolveEditableFieldsFunc(ctx, resourceType, resourceID, owningOUID, ouID)
	}
	panic("fakeSharingService: unexpected call to ResolveEditableFields")
}
