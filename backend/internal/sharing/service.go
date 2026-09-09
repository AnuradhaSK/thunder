// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package sharing

import (
	"context"
	"errors"
	"fmt"
	"slices"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"

	oupkg "github.com/thunder-id/thunderid/internal/ou"
	"github.com/thunder-id/thunderid/internal/system/cache"
	serverconst "github.com/thunder-id/thunderid/internal/system/constants"
	"github.com/thunder-id/thunderid/internal/system/log"
	"github.com/thunder-id/thunderid/internal/system/security"
	"github.com/thunder-id/thunderid/internal/system/sysauthz"
	"github.com/thunder-id/thunderid/internal/system/utils"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

const loggerComponentName = "SharingService"

// ServiceInterface is the generic, resource-type-agnostic sharing and templated-config engine.
// Every resource type onboards by registering a ResourceTypeDeclaration; no method here is
// specific to any one resource type.
type ServiceInterface interface {
	// RegisterResourceType adds a resource type's declaration to the framework. Safe to call
	// after Initialize, since a resource type's own store (needed by its SharingHooks) is
	// typically constructed after the sharing service itself.
	RegisterResourceType(decl ResourceTypeDeclaration)

	// Grants resourceID to other OU(s) per policy. actingOUID is the OU performing this
	// share: it may be owningOUID itself, which may use either policy mode (root-targeting, the
	// only way to cross into a different tree, or children-targeting, to fan out directly within
	// its own subtree); or it may be any other OU already visible for resourceID (via an earlier
	// call to this same method), which may only use children-targeting, to fan out further within
	// its own subtree — it can never use root-targeting. This is what makes a sharee resharing
	// what was shared to it subject to the exact same rule as the original share: the same
	// eligibility check (must be visible to act) and the same method, not a separate operation.
	// Fails with ErrorNotShared if actingOUID is not owningOUID and is not currently visible.
	Share(
		ctx context.Context, resourceType ResourceType, resourceID, owningOUID, actingOUID string,
		policy SharePolicy,
	) ([]Grant, *tidcommon.ServiceError)
	// ShareDeclarative records a grant declared by a declarative resource file. It applies exactly
	// the validation Share does — it is the same code path, so a malformed or ineligible declared
	// grant fails at startup just as it would through the API — but the resulting grant is held in
	// memory for the lifetime of the process instead of being written to RESOURCE_GRANT.
	//
	// That mirrors the resource itself: a declarative resource lives in its own file-backed store
	// and never reaches the database, so persisting its grants alone would leave rows orphaned
	// whenever the file changed, and would append a fresh duplicate of every grant on each restart
	// (Share does not deduplicate). Only declarative resource loaders should call this.
	ShareDeclarative(
		ctx context.Context, resourceType ResourceType, resourceID, owningOUID, actingOUID string,
		policy SharePolicy,
	) ([]Grant, *tidcommon.ServiceError)
	// Unshare revokes a grant (and any reshare grants that derive from it), invoking the
	// resource type's SharingHooks.OnUnshare for every OU that loses access as a result.
	Unshare(ctx context.Context, grantID string) *tidcommon.ServiceError
	// ListGrants lists every grant recorded for a resource (admin/audit view). Unbounded by
	// design: use it when the whole grant graph is needed at once. Prefer ListGrantsPage for
	// anything user-facing.
	ListGrants(
		ctx context.Context, resourceType ResourceType, resourceID string,
	) ([]Grant, *tidcommon.ServiceError)
	// ListGrantsPage lists one page of a resource's grants plus the total behind it, for the
	// admin/audit list endpoint. limit and offset are taken as given — the HTTP layer owning the
	// endpoint validates them, so its own error vocabulary is what a caller sees.
	//
	// Grants come from both sources: those stored in RESOURCE_GRANT and those a declarative
	// resource file declares, which are held in memory. The composite store merges them, stored
	// first, so paging over the combined set is stable.
	ListGrantsPage(
		ctx context.Context, resourceType ResourceType, resourceID string, limit, offset int,
	) (*GrantPage, *tidcommon.ServiceError)

	// ExportGrants returns every grant for resourceID as replayable (ActingOUID, SharePolicy)
	// pairs, in an order safe to apply sequentially via Share(): the sole mechanism for
	// recreating a resource's sharing state elsewhere (export/import round-tripping, and
	// declarative resource loading) — replaying each pair through Share(), in order, reproduces
	// an equivalent grant graph, going through the exact same validation a live API call would.
	// There is deliberately no separate "restore" primitive that bypasses Share()'s own checks.
	ExportGrants(
		ctx context.Context, resourceType ResourceType, resourceID string,
	) ([]ReplayableGrant, *tidcommon.ServiceError)

	// IsShared reports whether resourceID is visible to ouID (as owner or sharee).
	IsShared(ctx context.Context, resourceType ResourceType, resourceID, ouID string) (bool, *tidcommon.ServiceError)
	// ListSharedResourceIDs returns every resourceID of resourceType shared (directly or via
	// reshare) to ouID. It does not include resources owned by ouID itself.
	ListSharedResourceIDs(
		ctx context.Context, resourceType ResourceType, ouID string,
	) ([]string, *tidcommon.ServiceError)

	// ResolveEditability resolves whether fieldKey is editable by ouID: true unconditionally when
	// ouID is resourceID's owning OU, otherwise membership of fieldKey (or its declared
	// FallbackKey) in the EditableFields of the grant that makes resourceID visible to ouID.
	ResolveEditability(
		ctx context.Context, resourceType ResourceType, resourceID, owningOUID, ouID, fieldKey string,
	) (bool, *tidcommon.ServiceError)
	// ResolveEditableFields returns every templated field key of resourceType currently editable
	// by ouID for resourceID: every declared field when ouID is resourceID's owning OU, otherwise
	// whichever declared fields are members of the EditableFields of the grant that makes
	// resourceID visible to ouID. Backs a resource type's "what can I edit" metadata endpoint.
	ResolveEditableFields(
		ctx context.Context, resourceType ResourceType, resourceID, owningOUID, ouID string,
	) ([]string, *tidcommon.ServiceError)

	// RequireOwnership enforces the sharing framework's core invariant: a resource's core
	// (non-templated) configuration may only be created, modified, or deleted by its owning
	// organization unit — never by a sharee, no matter how privileged its grant. Only
	// templated fields (ResolveEditability) and assignments are ever editable by a sharee. Callers
	// holding the deployment's root permission, and internal runtime callers (bootstrap, flow
	// executors), are exempt, consistent with every other check in this framework.
	RequireOwnership(ctx context.Context, resourceType ResourceType, owningOUID string) *tidcommon.ServiceError

	// RequireOwnershipForDeletion enforces the identical invariant and bypass rules as
	// RequireOwnership, for the deletion path specifically. On rejection, it returns resourceType's
	// own DeletionOwnershipError if that resource type implements it, since "this resource cannot
	// be deleted by this organization unit" is naturally a resource-type-specific message rather
	// than the generic core-config-edit framing RequireOwnership uses; resource types that don't
	// implement DeletionOwnershipError get ErrorCoreConfigOwnerOnly, same as RequireOwnership.
	RequireOwnershipForDeletion(
		ctx context.Context, resourceType ResourceType, owningOUID string,
	) *tidcommon.ServiceError
}

// service is the default implementation of ServiceInterface.
type service struct {
	logger              log.Logger
	store               sharingStoreInterface
	registry            *registry
	ouHierarchyResolver sysauthz.OUHierarchyResolver
	ouService           oupkg.OrganizationUnitServiceInterface

	// declarativeStore holds the grants declared by declarative resource files, in memory. nil
	// when declarative resources are disabled, in which case ShareDeclarative is never called.
	// Seeded through ShareDeclarative and read back through the composite store in s.store.
	declarativeStore *declarativeGrantStore

	// Point-invalidated caches for the two read paths that would otherwise fan out across the
	// OU tree or hit the store on every call: editability resolution and share-graph visibility.
	// Both are cleared (not point-deleted) on writes, since a single policy/grant change can
	// affect an unbounded number of cached (resource, OU) keys — writes are rare/admin-only, so a
	// full clear is cheap relative to per-request resolution cost. nil when no cache manager was
	// provided (e.g. in unit tests constructing the service directly).
	editabilityCache cache.CacheInterface[bool]
	visibilityCache  cache.CacheInterface[bool]
	visibleIDsCache  cache.CacheInterface[[]string]

	transactioner providers.Transactioner

	// allowChildOUCrossTreeSharing controls whether a non-root organization unit may use
	// root-targeting to share a resource directly to a foreign tree's Root, rather than only its
	// own tree's Root. A static, deployment-wide setting (config.Config.ResourceSharing) read once at
	// startup, not a runtime-mutable server-config section: changing it requires a restart.
	allowChildOUCrossTreeSharing bool
}

// newService creates a new sharing service.
func newService(
	store sharingStoreInterface,
	declarativeStore *declarativeGrantStore,
	ouHierarchyResolver sysauthz.OUHierarchyResolver,
	ouService oupkg.OrganizationUnitServiceInterface,
	transactioner providers.Transactioner,
	editabilityCache cache.CacheInterface[bool],
	visibilityCache cache.CacheInterface[bool],
	visibleIDsCache cache.CacheInterface[[]string],
	allowChildOUCrossTreeSharing bool,
) ServiceInterface {
	return &service{
		logger:                       *log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName)), //nolint:lll
		store:                        store,
		declarativeStore:             declarativeStore,
		registry:                     newRegistry(),
		ouHierarchyResolver:          ouHierarchyResolver,
		ouService:                    ouService,
		transactioner:                transactioner,
		editabilityCache:             editabilityCache,
		visibilityCache:              visibilityCache,
		visibleIDsCache:              visibleIDsCache,
		allowChildOUCrossTreeSharing: allowChildOUCrossTreeSharing,
	}
}

// RegisterResourceType adds decl to the registry.
func (s *service) RegisterResourceType(decl ResourceTypeDeclaration) {
	s.registry.register(decl)
}

// Grants resourceID to other OU(s) per policy. See ServiceInterface for the full contract:
// actingOUID selects the mode (root-targeting requires actingOUID == owningOUID; children-
// targeting accepts any currently-visible actingOUID), and this single method is what makes a
// sharee resharing further subject to the exact same rule as the original share.
func (s *service) Share(
	ctx context.Context, resourceType ResourceType, resourceID, owningOUID, actingOUID string,
	policy SharePolicy,
) ([]Grant, *tidcommon.ServiceError) {
	if _, ok := s.registry.get(resourceType); !ok {
		return nil, &ErrorResourceTypeNotRegistered
	}
	if resourceID == "" || owningOUID == "" || actingOUID == "" {
		return nil, &ErrorInvalidRequestFormat
	}

	rootMode := policy.AllRoots || len(policy.RootOUIDs) > 0
	childrenMode := policy.AllChildren || len(policy.OUIDs) > 0 || len(policy.SubtreeOUIDs) > 0
	allOUsMode := policy.AllOUs
	selected := 0
	for _, on := range []bool{rootMode, childrenMode, allOUsMode} {
		if on {
			selected++
		}
	}
	if selected != 1 {
		// Exactly one mode must be selected: neither policy populated, or more than one, are both
		// invalid. Rejecting rather than silently preferring one keeps an ambiguous request from
		// creating a grant the caller did not mean to.
		return nil, &ErrorInvalidRequestFormat
	}

	if allOUsMode {
		if actingOUID != owningOUID {
			// Deployment-wide distribution is the owner's decision alone. A sharee resharing what
			// it received may only fan out within its own subtree (children-targeting), never to
			// every OU in the deployment.
			return nil, &ErrorInvalidTargetOU
		}
		return s.shareToAllOUs(ctx, resourceType, resourceID, owningOUID, policy)
	}
	if rootMode {
		if actingOUID != owningOUID {
			// Only the resource's own owner may cross into a different tree; a sharee has no
			// standing to name an arbitrary Root as a target.
			return nil, &ErrorInvalidTargetOU
		}
		return s.shareToRoots(ctx, resourceType, resourceID, owningOUID, policy)
	}
	return s.shareToChildren(ctx, resourceType, resourceID, owningOUID, actingOUID, policy)
}

// shareToAllOUs implements Share's deployment-wide mode: owningOUID makes resourceID visible to
// every OU at every depth, current and future, minus policy.ExcludedOUIDs and their subtrees.
// Unlike shareToRoots there is no cross-tree restriction to apply: the grant spans every tree by
// construction, so gating it on the owner's own tree would be meaningless. It remains owner-only
// (enforced by Share above), which is what keeps it from being a privilege-escalation path for a
// sharee.
func (s *service) shareToAllOUs(
	ctx context.Context, resourceType ResourceType, resourceID, owningOUID string, policy SharePolicy,
) ([]Grant, *tidcommon.ServiceError) {
	// Owner-only, so there is no acting grant to inherit editability from: the default, absent an
	// explicit list, is every declared field.
	editableFields, svcErr := s.resolveGrantEditableFields(
		resourceType, owningOUID, owningOUID, nil, policy.EditableFields)
	if svcErr != nil {
		return nil, svcErr
	}

	var grants []Grant
	var capturedSvcErr *tidcommon.ServiceError
	err := s.transactioner.Transact(ctx, func(txCtx context.Context) error {
		grant, svcErr := s.createGrant(
			txCtx, resourceType, resourceID, owningOUID,
			StageShare, TargetScopeAllOUs, "", "",
			policy.ExcludedOUIDs, editableFields,
		)
		if svcErr != nil {
			capturedSvcErr = svcErr
			return fmt.Errorf("%s", svcErr.Error.DefaultValue)
		}
		grants = append(grants, *grant)
		return nil
	})
	s.clearVisibilityCaches()
	if capturedSvcErr != nil {
		return nil, capturedSvcErr
	}
	if err != nil {
		s.logger.Error(ctx, "Failed to share resource to all organization units", log.Error(err))
		return nil, &tidcommon.InternalServerError
	}
	return grants, nil
}

// shareToRoots implements Share's root-targeting mode: owningOUID shares resourceID to Root(s).
func (s *service) shareToRoots(
	ctx context.Context, resourceType ResourceType, resourceID, owningOUID string, policy SharePolicy,
) ([]Grant, *tidcommon.ServiceError) {
	// Root-targeting is always owner-only (enforced by Share before this is called), so there is
	// no acting grant to inherit from: the default, absent an explicit list, is every declared field.
	editableFields, svcErr := s.resolveGrantEditableFields(
		resourceType, owningOUID, owningOUID, nil, policy.EditableFields)
	if svcErr != nil {
		return nil, svcErr
	}

	// A non-root owner may reach its own tree's root freely (the standard first step of
	// push-to-own-root-then-reshare); reaching a foreign tree's root instead is restricted unless
	// s.allowChildOUCrossTreeSharing (config.Config.ResourceSharing, a static deployment setting) is enabled.
	// A root owner is exempt from this check entirely: sharing directly to another root is
	// ordinary Root-to-Root distribution, not a child reaching outside its own tree. ownRootOUID
	// == owningOUID exactly when owningOUID is itself a root.
	ownRootOUID, svcErr := s.resolveOwnRootOUID(ctx, owningOUID)
	if svcErr != nil {
		return nil, svcErr
	}

	var grants []Grant
	var capturedSvcErr *tidcommon.ServiceError
	err := s.transactioner.Transact(ctx, func(txCtx context.Context) error {
		if policy.AllRoots {
			if owningOUID != ownRootOUID && !s.allowChildOUCrossTreeSharing {
				s.logger.Debug(txCtx, "AllRoots sharing is restricted for a non-root owner",
					log.String("owningOUID", owningOUID))
				capturedSvcErr = &ErrorCrossTreeShareRestricted
				return fmt.Errorf("%s", ErrorCrossTreeShareRestricted.Error.DefaultValue)
			}
			for _, excludedOUID := range policy.ExcludedRootOUIDs {
				isRoot, svcErr := s.isRootOU(txCtx, excludedOUID)
				if svcErr != nil {
					capturedSvcErr = svcErr
					return fmt.Errorf("%s", svcErr.Error.DefaultValue)
				}
				if !isRoot {
					s.logger.Debug(txCtx, "Share exclusion is not a root OU", log.String("ouID", excludedOUID))
					capturedSvcErr = &ErrorInvalidTargetOU
					return fmt.Errorf("%s", ErrorInvalidTargetOU.Error.DefaultValue)
				}
			}
			grant, svcErr := s.createGrant(txCtx, resourceType, resourceID, owningOUID,
				StageShare, TargetScopeAllRoots, "", "", policy.ExcludedRootOUIDs, editableFields)
			if svcErr != nil {
				capturedSvcErr = svcErr
				return fmt.Errorf("%s", svcErr.Error.DefaultValue)
			}
			grants = append(grants, *grant)
			return nil
		}

		for _, rootOUID := range policy.RootOUIDs {
			isRoot, svcErr := s.isRootOU(txCtx, rootOUID)
			if svcErr != nil {
				capturedSvcErr = svcErr
				return fmt.Errorf("%s", svcErr.Error.DefaultValue)
			}
			if !isRoot {
				s.logger.Debug(txCtx, "Share target is not a root OU", log.String("ouID", rootOUID))
				capturedSvcErr = &ErrorInvalidTargetOU
				return fmt.Errorf("%s", ErrorInvalidTargetOU.Error.DefaultValue)
			}
			if owningOUID != ownRootOUID && rootOUID != ownRootOUID && !s.allowChildOUCrossTreeSharing {
				s.logger.Debug(txCtx, "Cross-tree share target restricted for a non-root owner",
					log.String("owningOUID", owningOUID), log.String("targetRootOUID", rootOUID))
				capturedSvcErr = &ErrorCrossTreeShareRestricted
				return fmt.Errorf("%s", ErrorCrossTreeShareRestricted.Error.DefaultValue)
			}
			grant, svcErr := s.createGrant(txCtx, resourceType, resourceID, owningOUID,
				StageShare, TargetScopeRoot, rootOUID, "", nil, editableFields)
			if svcErr != nil {
				capturedSvcErr = svcErr
				return fmt.Errorf("%s", svcErr.Error.DefaultValue)
			}
			grants = append(grants, *grant)
		}
		return nil
	})
	if capturedSvcErr != nil {
		return nil, capturedSvcErr
	}
	if err != nil {
		s.logger.Error(ctx, "Failed to share resource", log.Error(err))
		return nil, &tidcommon.InternalServerError
	}

	s.clearVisibilityCaches()
	return grants, nil
}

// shareToChildren implements Share's children-targeting mode: actingOUID distributes resourceID
// into its own subtree per policy. actingOUID needs no preceding grant when it is the resource's
// own owner (owningOUID): the owner is always trivially visible to its own resource, so an owner
// can use this mode directly in one call. Any other actingOUID must already be visible for
// resourceID via some prior Share call, found by walking its ancestor chain the same way IsShared
// does — this is the check that makes a sharee resharing further subject to the same rule as the
// original share.
func (s *service) shareToChildren(
	ctx context.Context, resourceType ResourceType, resourceID, owningOUID, actingOUID string,
	policy SharePolicy,
) ([]Grant, *tidcommon.ServiceError) {
	// Stage reflects who is issuing the grant, not which target-scope mode was used: the owner
	// distributing directly into its own subtree is a first-hop grant (StageShare), exactly like
	// root-targeting, just aimed at its own children instead of a Root. Only a previously-visible
	// non-owner OU redistributing further is a reshare (StageReshare).
	stage := StageShare
	var parentGrantID string
	var actingGrant *Grant
	if actingOUID != owningOUID {
		stage = StageReshare
		visible, nearestGrant, svcErr := s.resolveNearestGrant(ctx, resourceType, resourceID, actingOUID)
		if svcErr != nil {
			return nil, svcErr
		}
		if !visible {
			return nil, &ErrorNotShared
		}
		parentGrantID = nearestGrant.ID
		actingGrant = nearestGrant

		// A reshare of something made visible by a declaratively declared grant records no parent.
		// The declared grant is held in memory, so RESOURCE_GRANT.PARENT_GRANT_ID — a foreign key
		// onto that same table — cannot reference it, and the insert would fail outright.
		// EditableFields is still inherited from it above, so what the reshare may carry is
		// unchanged; only the lineage link is dropped. See ListChildGrants for what that costs.
		if s.declarativeStore != nil && s.declarativeStore.Has(nearestGrant.ID) {
			parentGrantID = ""
		}
	}

	editableFields, svcErr := s.resolveGrantEditableFields(
		resourceType, owningOUID, actingOUID, actingGrant, policy.EditableFields)
	if svcErr != nil {
		return nil, svcErr
	}

	var grants []Grant
	var capturedSvcErr *tidcommon.ServiceError
	err := s.transactioner.Transact(ctx, func(txCtx context.Context) error {
		if policy.AllChildren {
			for _, excludedOUID := range policy.ExcludedOUIDs {
				withinSubtree, svcErr := s.isWithinSubtree(txCtx, excludedOUID, actingOUID)
				if svcErr != nil {
					capturedSvcErr = svcErr
					return fmt.Errorf("%s", svcErr.Error.DefaultValue)
				}
				if !withinSubtree {
					capturedSvcErr = &ErrorInvalidTargetOU
					return fmt.Errorf("%s", ErrorInvalidTargetOU.Error.DefaultValue)
				}
			}
			grant, svcErr := s.createGrant(txCtx, resourceType, resourceID, owningOUID,
				stage, TargetScopeAllChildren, actingOUID, parentGrantID, policy.ExcludedOUIDs, editableFields)
			if svcErr != nil {
				capturedSvcErr = svcErr
				return fmt.Errorf("%s", svcErr.Error.DefaultValue)
			}
			grants = append(grants, *grant)
			return nil
		}

		// Exclusions are only meaningful for the subtree-bearing targets below; an OUIDs grant
		// names one OU and reaches no further, so there is nothing under it to carve out.
		if len(policy.SubtreeOUIDs) > 0 {
			for _, excludedOUID := range policy.ExcludedOUIDs {
				withinSubtree, svcErr := s.isWithinSubtree(txCtx, excludedOUID, actingOUID)
				if svcErr != nil {
					capturedSvcErr = svcErr
					return fmt.Errorf("%s", svcErr.Error.DefaultValue)
				}
				if !withinSubtree {
					capturedSvcErr = &ErrorInvalidTargetOU
					return fmt.Errorf("%s", ErrorInvalidTargetOU.Error.DefaultValue)
				}
			}
		}

		for _, ouID := range policy.OUIDs {
			isImmediateChild, svcErr := s.isImmediateChildOf(txCtx, ouID, actingOUID)
			if svcErr != nil {
				capturedSvcErr = svcErr
				return fmt.Errorf("%s", svcErr.Error.DefaultValue)
			}
			if !isImmediateChild {
				capturedSvcErr = &ErrorInvalidTargetOU
				return fmt.Errorf("%s", ErrorInvalidTargetOU.Error.DefaultValue)
			}
			grant, svcErr := s.createGrant(txCtx, resourceType, resourceID, owningOUID,
				stage, TargetScopeOU, ouID, parentGrantID, nil, editableFields)
			if svcErr != nil {
				capturedSvcErr = svcErr
				return fmt.Errorf("%s", svcErr.Error.DefaultValue)
			}
			grants = append(grants, *grant)
		}

		// Same one-hop target rule as OUIDs above; the grant simply reaches the named child's whole
		// subtree instead of the child alone. Every exclusion is carried on every subtree grant:
		// one that falls outside a given child's subtree can never appear between that child and a
		// descendant of it, so it is inert there rather than wrong.
		for _, ouID := range policy.SubtreeOUIDs {
			isImmediateChild, svcErr := s.isImmediateChildOf(txCtx, ouID, actingOUID)
			if svcErr != nil {
				capturedSvcErr = svcErr
				return fmt.Errorf("%s", svcErr.Error.DefaultValue)
			}
			if !isImmediateChild {
				capturedSvcErr = &ErrorInvalidTargetOU
				return fmt.Errorf("%s", ErrorInvalidTargetOU.Error.DefaultValue)
			}
			grant, svcErr := s.createGrant(txCtx, resourceType, resourceID, owningOUID,
				stage, TargetScopeOUSubtree, ouID, parentGrantID, policy.ExcludedOUIDs, editableFields)
			if svcErr != nil {
				capturedSvcErr = svcErr
				return fmt.Errorf("%s", svcErr.Error.DefaultValue)
			}
			grants = append(grants, *grant)
		}
		return nil
	})
	if capturedSvcErr != nil {
		return nil, capturedSvcErr
	}
	if err != nil {
		s.logger.Error(ctx, "Failed to reshare resource", log.Error(err))
		return nil, &tidcommon.InternalServerError
	}

	s.clearVisibilityCaches()
	return grants, nil
}

// ShareDeclarative records a declared grant in memory rather than persisting it. See
// ServiceInterface for why. It reuses Share wholesale, marking the context so that the single
// write point, createGrant, seeds the declarative store instead of the database.
func (s *service) ShareDeclarative(
	ctx context.Context, resourceType ResourceType, resourceID, owningOUID, actingOUID string,
	policy SharePolicy,
) ([]Grant, *tidcommon.ServiceError) {
	if s.declarativeStore == nil {
		s.logger.Error(ctx, "Declarative grant declared while declarative resources are disabled",
			log.String("resourceType", string(resourceType)), log.String("resourceID", resourceID))
		return nil, &tidcommon.InternalServerError
	}
	return s.Share(withDeclarativeLoad(ctx), resourceType, resourceID, owningOUID, actingOUID, policy)
}

// Unshare revokes a grant (and any reshare grants deriving from it), invoking SharingHooks for
// every OU that loses access.
func (s *service) Unshare(ctx context.Context, grantID string) *tidcommon.ServiceError {
	// Refuse a declaratively declared grant before any hook fires or any descendant is touched:
	// the store would reject the delete at the end anyway, and rolling back is a worse way to say
	// no than not starting.
	if s.declarativeStore != nil && s.declarativeStore.Has(grantID) {
		s.logger.Debug(ctx, "Refused to revoke a declaratively declared grant",
			log.String("grantID", grantID))
		return &ErrorGrantDeclarative
	}

	var capturedSvcErr *tidcommon.ServiceError
	err := s.transactioner.Transact(ctx, func(txCtx context.Context) error {
		if svcErr := s.unshareRecursive(txCtx, grantID); svcErr != nil {
			capturedSvcErr = svcErr
			return fmt.Errorf("%s", svcErr.Error.DefaultValue)
		}
		return nil
	})
	s.clearVisibilityCaches()
	if capturedSvcErr != nil {
		return capturedSvcErr
	}
	if err != nil {
		s.logger.Error(ctx, "Failed to unshare resource", log.Error(err))
		return &tidcommon.InternalServerError
	}
	return nil
}

// unshareRecursive processes a grant's descendants (deepest first) before the grant itself, so
// every affected OU's SharingHooks.OnUnshare fires exactly once, then deletes the grant.
func (s *service) unshareRecursive(ctx context.Context, grantID string) *tidcommon.ServiceError {
	grant, err := s.store.GetGrant(ctx, grantID)
	if err != nil {
		if errors.Is(err, ErrGrantNotFound) {
			return &ErrorGrantNotFound
		}
		s.logger.Error(ctx, "Failed to get grant", log.Error(err))
		return &tidcommon.InternalServerError
	}

	children, err := s.store.ListChildGrants(ctx, grantID)
	if err != nil {
		s.logger.Error(ctx, "Failed to list child grants", log.Error(err))
		return &tidcommon.InternalServerError
	}
	for _, child := range children {
		if svcErr := s.unshareRecursive(ctx, child.ID); svcErr != nil {
			return svcErr
		}
	}

	if svcErr := s.fireUnshareHooks(ctx, grant); svcErr != nil {
		return svcErr
	}

	if err := s.store.DeleteGrant(ctx, grantID); err != nil {
		// A grant a declarative file declares is not revocable here; the file is what changes it.
		if errors.Is(err, ErrGrantDeclarative) {
			s.logger.Debug(ctx, "Refused to revoke a declaratively declared grant",
				log.String("grantID", grantID))
			return &ErrorGrantDeclarative
		}
		s.logger.Error(ctx, "Failed to delete grant", log.Error(err))
		return &tidcommon.InternalServerError
	}
	return nil
}

// fireUnshareHooks resolves the concrete OU(s) affected by grant and invokes the resource type's
// SharingHooks.OnUnshare for each.
func (s *service) fireUnshareHooks(ctx context.Context, grant Grant) *tidcommon.ServiceError {
	decl, ok := s.registry.get(grant.ResourceType)
	if !ok {
		return nil
	}
	hooks, ok := decl.(SharingHooks)
	if !ok {
		return nil
	}

	ouIDs, svcErr := s.resolveGrantOUIDs(ctx, grant)
	if svcErr != nil {
		return svcErr
	}
	for _, ouID := range ouIDs {
		if err := hooks.OnUnshare(ctx, grant.ResourceID, ouID); err != nil {
			s.logger.Error(ctx, "Sharing hook failed during unshare",
				log.String("resourceType", string(grant.ResourceType)),
				log.String("resourceID", grant.ResourceID), log.String("ouID", ouID), log.Error(err))
			return &tidcommon.InternalServerError
		}
	}
	return nil
}

// resolveGrantOUIDs returns the concrete set of OUs a grant currently makes resourceID visible
// to. For TargetScopeAllRoots, no enumeration is performed: this is a documented, narrow scope
// reduction (see package doc note on Unshare) — revoking an "all roots" grant stops it from
// governing any *future* reshare or assignment, but does not retroactively enumerate and purge
// every root OU's per-OU state, since the OU package exposes no "list all root OUs" query today.
func (s *service) resolveGrantOUIDs(ctx context.Context, grant Grant) ([]string, *tidcommon.ServiceError) {
	switch grant.TargetScope {
	case TargetScopeOU, TargetScopeRoot:
		if grant.TargetOUID == "" {
			return []string{}, nil
		}
		return []string{grant.TargetOUID}, nil
	case TargetScopeAllChildren:
		return s.listSubtreeOUIDs(ctx, grant.TargetOUID, grant.ExcludedOUIDs)
	case TargetScopeOUSubtree:
		// listSubtreeOUIDs enumerates below the anchor but not the anchor itself, and here the
		// anchor is a target in its own right, so it is prepended.
		if grant.TargetOUID == "" {
			return []string{}, nil
		}
		subtree, svcErr := s.listSubtreeOUIDs(ctx, grant.TargetOUID, grant.ExcludedOUIDs)
		if svcErr != nil {
			return nil, svcErr
		}
		return append([]string{grant.TargetOUID}, subtree...), nil
	case TargetScopeAllRoots:
		s.logger.Warn(ctx, "Unsharing an all-roots grant does not retroactively purge per-OU state "+
			"for every root OU; only future access is revoked",
			log.String("resourceType", string(grant.ResourceType)), log.String("resourceID", grant.ResourceID))
		return []string{}, nil
	case TargetScopeAllOUs:
		// Same documented, narrow scope reduction as TargetScopeAllRoots above, for the same
		// reason: enumerating every OU in the deployment to fire per-OU cleanup is unbounded work
		// on an admin path, and the OU package exposes no whole-deployment enumeration. Revoking
		// the grant stops it governing any future reshare or assignment; it does not retroactively
		// purge per-OU state each OU accumulated while it was in force.
		s.logger.Warn(ctx, "Unsharing an all-organization-units grant does not retroactively purge "+
			"per-OU state for every organization unit; only future access is revoked",
			log.String("resourceType", string(grant.ResourceType)), log.String("resourceID", grant.ResourceID))
		return []string{}, nil
	default:
		return []string{}, nil
	}
}

// listSubtreeOUIDs returns every OU ID in the subtree rooted at (but excluding) anchorOUID, via
// breadth-first traversal of GetOrganizationUnitChildren, skipping any OU listed in excluded and
// its entire subtree (that subtree was never made visible by the grant in the first place, so it
// must not have OnUnshare fired for it). This is an admin/write-path operation (unshare), not the
// per-request resolve/list hot path, so a bounded tree walk here is acceptable.
func (s *service) listSubtreeOUIDs(
	ctx context.Context, anchorOUID string, excluded []string,
) ([]string, *tidcommon.ServiceError) {
	excludedSet := make(map[string]struct{}, len(excluded))
	for _, id := range excluded {
		excludedSet[id] = struct{}{}
	}

	var result []string
	queue := []string{anchorOUID}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		offset := 0
		for {
			resp, svcErr := s.ouService.GetOrganizationUnitChildren(ctx, current, serverconst.MaxPageSize, offset, nil)
			if svcErr != nil {
				return nil, svcErr
			}
			for _, child := range resp.OrganizationUnits {
				if _, isExcluded := excludedSet[child.ID]; isExcluded {
					continue
				}
				result = append(result, child.ID)
				queue = append(queue, child.ID)
			}
			offset += len(resp.OrganizationUnits)
			if len(resp.OrganizationUnits) == 0 || offset >= resp.TotalResults {
				break
			}
		}
	}
	return result, nil
}

// ListGrants lists every grant recorded for a resource.
func (s *service) ListGrants(
	ctx context.Context, resourceType ResourceType, resourceID string,
) ([]Grant, *tidcommon.ServiceError) {
	grants, err := s.store.ListGrantsForResource(ctx, resourceType, resourceID)
	if err != nil {
		s.logger.Error(ctx, "Failed to list grants", log.Error(err))
		return nil, &tidcommon.InternalServerError
	}
	return grants, nil
}

// ListGrantsPage lists one page of a resource's grants. See ServiceInterface for the contract.
func (s *service) ListGrantsPage(
	ctx context.Context, resourceType ResourceType, resourceID string, limit, offset int,
) (*GrantPage, *tidcommon.ServiceError) {
	total, err := s.store.CountGrantsForResource(ctx, resourceType, resourceID)
	if err != nil {
		s.logger.Error(ctx, "Failed to count grants", log.Error(err))
		return nil, &tidcommon.InternalServerError
	}

	// Skip the page query when the offset is already past the end: the count alone is enough to
	// render an empty page with correct links.
	grants := []Grant{}
	if offset < total {
		grants, err = s.store.ListGrantsForResourcePage(ctx, resourceType, resourceID, limit, offset)
		if err != nil {
			s.logger.Error(ctx, "Failed to list grants page", log.Error(err))
			return nil, &tidcommon.InternalServerError
		}
	}

	return &GrantPage{Grants: grants, TotalResults: total}, nil
}

// ExportGrants converts resourceID's current grants into replayable (ActingOUID, SharePolicy)
// pairs. See ServiceInterface.ExportGrants for the contract.
func (s *service) ExportGrants(
	ctx context.Context, resourceType ResourceType, resourceID string,
) ([]ReplayableGrant, *tidcommon.ServiceError) {
	grants, svcErr := s.ListGrants(ctx, resourceType, resourceID)
	if svcErr != nil {
		return nil, svcErr
	}
	if len(grants) == 0 {
		return nil, nil
	}

	ordered, svcErr := orderGrantsByDependency(grants)
	if svcErr != nil {
		return nil, svcErr
	}

	replayable := make([]ReplayableGrant, 0, len(ordered))
	for _, grant := range ordered {
		actingOUID, svcErr := s.grantActingOUID(ctx, grant)
		if svcErr != nil {
			return nil, svcErr
		}
		replayable = append(replayable, ReplayableGrant{
			ActingOUID: actingOUID,
			Policy:     policyFromGrant(grant),
		})
	}
	return replayable, nil
}

// grantActingOUID derives which OU issued grant, purely from its own stored fields: the owner
// itself for any share-stage grant (root- or children-targeting, per shareToRoots/shareToChildren
// — both are only ever owner-issued at Stage: share); the anchor OU itself for an all_children
// reshare (shareToChildren stores actingOUID as TargetOUID in that mode); the immediate parent of
// TargetOUID for an explicit-OU reshare (the rule that an explicit reshare target must be the
// issuer's own direct child makes this always resolvable with a single ancestor lookup).
func (s *service) grantActingOUID(ctx context.Context, grant Grant) (string, *tidcommon.ServiceError) {
	if grant.Stage == StageShare {
		return grant.OwningOUID, nil
	}
	if grant.TargetScope == TargetScopeAllChildren {
		return grant.TargetOUID, nil
	}
	ancestors, svcErr := s.ouHierarchyResolver.GetAncestorOUIDs(ctx, grant.TargetOUID)
	if svcErr != nil {
		return "", svcErr
	}
	if len(ancestors) == 0 {
		s.logger.Error(ctx, "Reshare target has no ancestors; cannot derive issuing OU",
			log.String("grantID", grant.ID), log.String("targetOUID", grant.TargetOUID))
		return "", &tidcommon.InternalServerError
	}
	return ancestors[0], nil
}

// policyFromGrant converts one already-materialized grant back into the SharePolicy that would
// recreate it via Share() — the inverse of shareToRoots'/shareToChildren's own grant construction.
func policyFromGrant(grant Grant) SharePolicy {
	switch grant.TargetScope {
	case TargetScopeAllOUs:
		return SharePolicy{
			AllOUs: true, ExcludedOUIDs: grant.ExcludedOUIDs, EditableFields: grant.EditableFields,
		}
	case TargetScopeAllRoots:
		return SharePolicy{
			AllRoots: true, ExcludedRootOUIDs: grant.ExcludedOUIDs, EditableFields: grant.EditableFields,
		}
	case TargetScopeRoot:
		return SharePolicy{RootOUIDs: []string{grant.TargetOUID}, EditableFields: grant.EditableFields}
	case TargetScopeAllChildren:
		return SharePolicy{
			AllChildren: true, ExcludedOUIDs: grant.ExcludedOUIDs, EditableFields: grant.EditableFields,
		}
	case TargetScopeOUSubtree:
		return SharePolicy{
			SubtreeOUIDs:   []string{grant.TargetOUID},
			ExcludedOUIDs:  grant.ExcludedOUIDs,
			EditableFields: grant.EditableFields,
		}
	default: // TargetScopeOU
		return SharePolicy{OUIDs: []string{grant.TargetOUID}, EditableFields: grant.EditableFields}
	}
}

// orderGrantsByDependency sorts grants so a parent (per ParentGrantID) always precedes any grant
// that names it — the order Share() calls must be replayed in for a multi-hop reshare chain to
// stay valid at each step. A resource's grants always form a forest (each reshare's ParentGrantID
// points to exactly one earlier grant for the same resource), so repeated passes collecting
// grants whose parent has already been placed (or which have no parent at all) terminate with
// every grant ordered. A grant whose parent never appears in the set — which should never happen,
// since reshare lineage is always within the same resource's own grant list — is treated as an
// internal error rather than silently dropped or misordered.
func orderGrantsByDependency(grants []Grant) ([]Grant, *tidcommon.ServiceError) {
	ordered := make([]Grant, 0, len(grants))
	placed := make(map[string]bool, len(grants))
	remaining := grants
	for len(remaining) > 0 {
		var next []Grant
		for _, g := range remaining {
			if g.ParentGrantID == "" || placed[g.ParentGrantID] {
				ordered = append(ordered, g)
				placed[g.ID] = true
				continue
			}
			next = append(next, g)
		}
		if len(next) == len(remaining) {
			return nil, &tidcommon.InternalServerError
		}
		remaining = next
	}
	return ordered, nil
}

// IsShared reports whether resourceID is visible to ouID (as its owner, or via a chain of one or
// more Share/Reshare grants reaching it).
func (s *service) IsShared(
	ctx context.Context, resourceType ResourceType, resourceID, ouID string,
) (bool, *tidcommon.ServiceError) {
	cacheKey := cache.CacheKey{Key: fmt.Sprintf("%s:%s:%s", resourceType, resourceID, ouID)}
	if s.visibilityCache != nil {
		if cached, ok := s.visibilityCache.Get(ctx, cacheKey); ok {
			return cached, nil
		}
	}

	visible, _, svcErr := s.resolveNearestGrant(ctx, resourceType, resourceID, ouID)
	if svcErr != nil {
		return false, svcErr
	}

	if s.visibilityCache != nil {
		_ = s.visibilityCache.Set(ctx, cacheKey, visible)
	}
	return visible, nil
}

// resolveNearestGrant reports whether resourceID is visible to ouID and, if so, the single grant
// that establishes it (the most specific/most recent hop in its delegation chain — see
// evaluateChainVisibility). The grant is nil both when ouID is not visible at all and when ouID is
// resourceID's own owning OU (trivially visible, needing no grant) — callers that care about that
// distinction (editability resolution) special-case the owner before calling this. Callers needing
// only a boolean (IsShared) or the grant's own attributes both go through this one lookup.
func (s *service) resolveNearestGrant(
	ctx context.Context, resourceType ResourceType, resourceID, ouID string,
) (visible bool, grant *Grant, svcErr *tidcommon.ServiceError) {
	grants, err := s.store.ListGrantsForResource(ctx, resourceType, resourceID)
	if err != nil {
		s.logger.Error(ctx, "Failed to list grants", log.Error(err))
		return false, nil, &tidcommon.InternalServerError
	}
	chain, svcErr := s.buildTopDownChain(ctx, ouID)
	if svcErr != nil {
		return false, nil, svcErr
	}
	visible, _, nearestGrant := evaluateChainVisibility(chain, grants)
	return visible, nearestGrant, nil
}

// ListSharedResourceIDs returns every resourceID of resourceType shared to ouID (owned resources
// are never included, regardless of what other grants might otherwise seem to cover them).
func (s *service) ListSharedResourceIDs(
	ctx context.Context, resourceType ResourceType, ouID string,
) ([]string, *tidcommon.ServiceError) {
	cacheKey := cache.CacheKey{Key: fmt.Sprintf("%s:%s", resourceType, ouID)}
	if s.visibleIDsCache != nil {
		if cached, ok := s.visibleIDsCache.Get(ctx, cacheKey); ok {
			return cached, nil
		}
	}

	chain, svcErr := s.buildTopDownChain(ctx, ouID)
	if svcErr != nil {
		return nil, svcErr
	}
	grants, err := s.store.ListGrantsRelevantToChain(ctx, resourceType, chain)
	if err != nil {
		s.logger.Error(ctx, "Failed to list grants", log.Error(err))
		return nil, &tidcommon.InternalServerError
	}

	grantsByResource := make(map[string][]Grant)
	var order []string
	for _, g := range grants {
		if _, ok := grantsByResource[g.ResourceID]; !ok {
			order = append(order, g.ResourceID)
		}
		grantsByResource[g.ResourceID] = append(grantsByResource[g.ResourceID], g)
	}

	ids := make([]string, 0, len(order))
	for _, resourceID := range order {
		visible, owningOUID, _ := evaluateChainVisibility(chain, grantsByResource[resourceID])
		if visible && owningOUID != ouID {
			ids = append(ids, resourceID)
		}
	}

	if s.visibleIDsCache != nil {
		_ = s.visibleIDsCache.Set(ctx, cacheKey, ids)
	}
	return ids, nil
}

// ResolveEditability resolves whether fieldKey is editable by ouID: true unconditionally when
// ouID owns resourceID, otherwise membership of fieldKey (or its FallbackKey) in the EditableFields
// of the grant that makes resourceID visible to ouID.
func (s *service) ResolveEditability(
	ctx context.Context, resourceType ResourceType, resourceID, owningOUID, ouID, fieldKey string,
) (bool, *tidcommon.ServiceError) {
	cacheKey := cache.CacheKey{
		Key: fmt.Sprintf("%s:%s:%s:%s:%s", resourceType, resourceID, owningOUID, ouID, fieldKey),
	}
	if s.editabilityCache != nil {
		if cached, ok := s.editabilityCache.Get(ctx, cacheKey); ok {
			return cached, nil
		}
	}

	field, ok := s.registry.templatedField(resourceType, fieldKey)
	if !ok {
		return false, &ErrorFieldNotTemplated
	}

	var grant *Grant
	if ouID != owningOUID {
		visible, nearestGrant, svcErr := s.resolveNearestGrant(ctx, resourceType, resourceID, ouID)
		if svcErr != nil {
			return false, svcErr
		}
		if visible {
			grant = nearestGrant
		}
	}
	editable := s.resolveFieldEditability(owningOUID, ouID, field, grant)

	if s.editabilityCache != nil {
		_ = s.editabilityCache.Set(ctx, cacheKey, editable)
	}
	return editable, nil
}

// ResolveEditableFields returns every templated field key of resourceType currently editable by
// ouID for resourceID (see ServiceInterface).
func (s *service) ResolveEditableFields(
	ctx context.Context, resourceType ResourceType, resourceID, owningOUID, ouID string,
) ([]string, *tidcommon.ServiceError) {
	decl, ok := s.registry.get(resourceType)
	if !ok {
		return nil, &ErrorResourceTypeNotRegistered
	}

	var grant *Grant
	if ouID != owningOUID {
		visible, nearestGrant, svcErr := s.resolveNearestGrant(ctx, resourceType, resourceID, ouID)
		if svcErr != nil {
			return nil, svcErr
		}
		if visible {
			grant = nearestGrant
		}
	}

	return s.effectiveEditableFieldKeys(decl.TemplatedFields(), owningOUID, ouID, grant), nil
}

// effectiveEditableFieldKeys evaluates resolveFieldEditability for every declared field, returning
// the keys that resolve editable. grant is the already-resolved nearest grant for ouID (nil when
// ouID is owningOUID, or when resourceID is not shared to ouID at all).
func (s *service) effectiveEditableFieldKeys(
	fields []TemplatedFieldDeclaration, owningOUID, ouID string, grant *Grant,
) []string {
	editableKeys := make([]string, 0, len(fields))
	for _, field := range fields {
		if s.resolveFieldEditability(owningOUID, ouID, field, grant) {
			editableKeys = append(editableKeys, field.Key)
		}
	}
	return editableKeys
}

// resolveFieldEditability resolves one field for one OU given an already-resolved grant (or nil,
// meaning resourceID is not shared to ouID at all). The owning OU always fully controls its own
// resource, checked before anything else; otherwise a field is editable only if it (or its
// coarser FallbackKey) is a member of grant.EditableFields.
func (s *service) resolveFieldEditability(
	owningOUID, ouID string, field TemplatedFieldDeclaration, grant *Grant,
) bool {
	if ouID == owningOUID {
		return true
	}
	if grant == nil {
		return false
	}
	if slices.Contains(grant.EditableFields, field.Key) {
		return true
	}
	return field.FallbackKey != "" && slices.Contains(grant.EditableFields, field.FallbackKey)
}

// resolveGrantEditableFields resolves the EditableFields to materialize on a new grant. When
// actingOUID is the resource's own owning OU, the default (an empty requested list) is every
// declared field, and an explicit list is validated against the declared fields. Otherwise
// (actingOUID is a sharee reshare), the default is exactly actingOUID's own current editable set
// (effectiveEditableFieldKeys against actingGrant, the grant that makes resourceID visible to
// actingOUID), and an explicit list must be a subset of that set — a reshare may only narrow
// editability relative to its own, never widen it.
func (s *service) resolveGrantEditableFields(
	resourceType ResourceType, owningOUID, actingOUID string, actingGrant *Grant, requested []string,
) ([]string, *tidcommon.ServiceError) {
	decl, ok := s.registry.get(resourceType)
	if !ok {
		return nil, &ErrorResourceTypeNotRegistered
	}
	fields := decl.TemplatedFields()

	if actingOUID == owningOUID {
		if len(requested) == 0 {
			return fieldKeys(fields), nil
		}
		for _, key := range requested {
			if _, ok := s.registry.templatedField(resourceType, key); !ok {
				return nil, &ErrorFieldNotTemplated
			}
		}
		return dedupeStrings(requested), nil
	}

	inherited := s.effectiveEditableFieldKeys(fields, owningOUID, actingOUID, actingGrant)
	if len(requested) == 0 {
		return inherited, nil
	}
	for _, key := range requested {
		if !slices.Contains(inherited, key) {
			return nil, &ErrorEditabilityCannotBeExpanded
		}
	}
	return dedupeStrings(requested), nil
}

// fieldKeys returns the Key of every declared field.
func fieldKeys(fields []TemplatedFieldDeclaration) []string {
	keys := make([]string, len(fields))
	for i, f := range fields {
		keys[i] = f.Key
	}
	return keys
}

// RequireOwnership rejects the call unless the caller's own organization unit (from the security
// context) is owningOUID, or the caller holds the deployment's root permission. resourceType is
// accepted for logging/future extensibility only; the check itself needs no registry lookup or
// store access, since core-config ownership is a hard rule, not a resolved policy.
func (s *service) RequireOwnership(
	ctx context.Context, resourceType ResourceType, owningOUID string,
) *tidcommon.ServiceError {
	if security.IsRuntimeContext(ctx) || security.HasSystemPermission(security.GetPermissions(ctx)) {
		return nil
	}
	if security.GetOUID(ctx) != owningOUID {
		s.logger.Debug(ctx, "Rejected core config mutation: caller does not own the resource",
			log.String("resourceType", string(resourceType)), log.String("owningOUID", owningOUID))
		return &ErrorCoreConfigOwnerOnly
	}
	return nil
}

// RequireOwnershipForDeletion applies the identical ownership/bypass rule as RequireOwnership, but
// on rejection prefers resourceType's own DeletionOwnershipError (if it implements that optional
// capability) over the generic ErrorCoreConfigOwnerOnly, since "this resource cannot be deleted by
// this organization unit" is a resource-type-specific message, not a core-config-edit one.
func (s *service) RequireOwnershipForDeletion(
	ctx context.Context, resourceType ResourceType, owningOUID string,
) *tidcommon.ServiceError {
	if security.IsRuntimeContext(ctx) || security.HasSystemPermission(security.GetPermissions(ctx)) {
		return nil
	}
	if security.GetOUID(ctx) == owningOUID {
		return nil
	}
	s.logger.Debug(ctx, "Rejected deletion: caller does not own the resource",
		log.String("resourceType", string(resourceType)), log.String("owningOUID", owningOUID))
	if decl, ok := s.registry.get(resourceType); ok {
		if provider, ok := decl.(DeletionOwnershipError); ok {
			return provider.ErrorResourceDeletionRestrictedToOwner()
		}
	}
	return &ErrorCoreConfigOwnerOnly
}

// clearVisibilityCaches invalidates every cached share-graph visibility result and every cached
// editability resolution: a single share/reshare/unshare call changes the grant graph, which both
// visibility and (since editability is resolved from the nearest grant) editability are derived
// from. A single such call can affect an unbounded number of cached (resource, OU[, field]) keys,
// and these calls are rare/admin-only, so a full clear is simpler and cheaper overall than
// tracking precise dependency sets.
func (s *service) clearVisibilityCaches() {
	if s.visibilityCache != nil {
		_ = s.visibilityCache.Clear(context.Background())
	}
	if s.visibleIDsCache != nil {
		_ = s.visibleIDsCache.Clear(context.Background())
	}
	if s.editabilityCache != nil {
		_ = s.editabilityCache.Clear(context.Background())
	}
}

// buildTopDownChain returns the chain from ouID's tree root down to ouID itself (root first, ouID
// last), via a single ancestor-chain lookup — the anchored lookup that keeps visibility
// resolution to one traversal regardless of tree depth or breadth. evaluateChainVisibility walks
// this same slice to resolve access.
func (s *service) buildTopDownChain(ctx context.Context, ouID string) ([]string, *tidcommon.ServiceError) {
	ancestors, svcErr := s.ouHierarchyResolver.GetAncestorOUIDs(ctx, ouID) // nearest-first: parent...root
	if svcErr != nil {
		return nil, svcErr
	}
	chain := make([]string, 0, len(ancestors)+1)
	for i := len(ancestors) - 1; i >= 0; i-- {
		chain = append(chain, ancestors[i])
	}
	return append(chain, ouID), nil
}

// evaluateChainVisibility walks chain (root first, target OU last) against every grant recorded
// for one resource and reports whether the last element is visible, that resource's owning OU
// (read directly off the grants, since every grant for a resource carries the same OwningOUID),
// and the specific grant that established the target's own visibility (nil when the target OU is
// the owner itself, which needs no grant).
//
// A position in the chain is covered if it is the owning OU (unconditional, wherever it sits in
// the chain — this is what lets an owner distribute directly into its own subtree, root or not,
// with no preceding grant of its own), or the tree's root has an incoming root-targeting grant
// (all_roots, or root-specific — always Stage: share, since only the owner may use that mode), or
// some earlier covered position in the chain has an all_children grant reaching this deep with no
// exclusion in between, or the immediately preceding position has an explicit "ou" grant naming
// this exact OU (both of the latter two may be Stage: share, when the owner issued them directly,
// or Stage: reshare, when a previously-visible sharee issued them further — Stage records who
// issued a grant, not whether it is traversable). That last case is deliberately restricted to the
// immediate predecessor only: an explicit grant never authorizes skipping a hop, so a broken or
// missing link anywhere in the chain — including one caused by an exclusion — cuts off every
// position below it, even if some row in the data happens to name a deeper OU directly.
//
// When more than one grant covers the same position (e.g. a blanket all_children grant from the
// owner and a narrower reshare issued by a closer intermediate OU both reach the same descendant),
// the deepest/most specific covering grant is preferred for nearestGrant — see the ancestor scan
// order below — since that is the grant that actually governs what was most recently delegated to
// this OU, not merely the ancestor grant that happens to also, incidentally, reach this far.
func evaluateChainVisibility(
	chain []string, grants []Grant,
) (visible bool, owningOUID string, nearestGrant *Grant) {
	if len(chain) == 0 || len(grants) == 0 {
		return false, "", nil
	}
	owningOUID = grants[0].OwningOUID

	covered := make([]bool, len(chain))
	coveredBy := make([]*Grant, len(chain))

	for i, ouID := range chain {
		if ouID == owningOUID {
			covered[i] = true
			continue
		}
		if i == 0 {
			for gi := range grants {
				g := &grants[gi]
				if g.Stage != StageShare {
					continue
				}
				if g.TargetScope == TargetScopeAllRoots && !slices.Contains(g.ExcludedOUIDs, ouID) {
					covered[0], coveredBy[0] = true, g
				}
				if g.TargetScope == TargetScopeRoot && g.TargetOUID == ouID {
					covered[0], coveredBy[0] = true, g
				}
			}
			if !covered[0] {
				covered[0], coveredBy[0] = coverageByAllOUs(chain[:1], grants)
			}
			continue
		}

		// Scan ancestors deepest-first so the recorded coveredBy (nearestGrant) is the most
		// specific/most recent grant actually covering this OU, not merely the first (shallowest)
		// one found — a broad upstream AllChildren grant must never shadow a narrower reshare
		// issued by a closer intermediate OU (this matters once nearestGrant is reused to resolve
		// editability, where the narrower grant is authoritative). At the immediate predecessor
		// (j == i-1), an explicit "ou" grant is exactly as near as an all_children grant anchored
		// there — both are checked before ever falling back to a more distant ancestor's
		// all_children grant, so a closer, more specific reshare always wins over a broader one
		// issued further up the chain, regardless of which of the two grant shapes it used.
		for j := i - 1; j >= 0 && !covered[i]; j-- {
			if !covered[j] {
				continue
			}
			for gi := range grants {
				g := &grants[gi]
				// An ou_subtree grant anchors its named OU's own subtree, so from the anchor
				// downwards it behaves exactly as an all_children grant issued by that OU would.
				if g.TargetScope != TargetScopeAllChildren && g.TargetScope != TargetScopeOUSubtree {
					continue
				}
				if g.TargetOUID != chain[j] {
					continue
				}
				excludedBetween := false
				for _, mid := range chain[j+1 : i+1] {
					if slices.Contains(g.ExcludedOUIDs, mid) {
						excludedBetween = true
						break
					}
				}
				if !excludedBetween {
					covered[i], coveredBy[i] = true, g
					break
				}
			}
			if !covered[i] && j == i-1 {
				for gi := range grants {
					g := &grants[gi]
					// ou_subtree covers its own named OU as well as the subtree below it, and is
					// subject to the same immediate-predecessor rule as a plain ou grant: both name
					// a direct child of the issuer, so neither ever authorizes skipping a hop.
					if g.TargetScope != TargetScopeOU && g.TargetScope != TargetScopeOUSubtree {
						continue
					}
					if g.TargetOUID == ouID {
						covered[i], coveredBy[i] = true, g
						break
					}
				}
			}
		}

		// Deployment-wide fallback, checked only after every specific grant has been tried, so a
		// narrower grant covering this same OU stays the recorded nearestGrant (which editability
		// resolution treats as authoritative). Unlike the scopes above this needs no covered
		// ancestor: an all_ous grant reaches every OU directly, so a descendant is visible through
		// it even when no hop above it is covered by anything else.
		if !covered[i] {
			covered[i], coveredBy[i] = coverageByAllOUs(chain[:i+1], grants)
		}
	}

	last := len(chain) - 1
	return covered[last], owningOUID, coveredBy[last]
}

// coverageByAllOUs reports whether a deployment-wide (all_ous) share-stage grant covers the OU
// at the end of ancestryToOU, which is the chain from the tree root down to and including that
// OU. The whole ancestry is tested, not just the OU itself: excluding an OU from an all_ous
// grant must cut off everything beneath it too, mirroring how an excluded Root's subtree is cut
// off by being unreachable through the root position.
func coverageByAllOUs(ancestryToOU []string, grants []Grant) (bool, *Grant) {
	for gi := range grants {
		g := &grants[gi]
		if g.Stage != StageShare || g.TargetScope != TargetScopeAllOUs {
			continue
		}
		excluded := false
		for _, hop := range ancestryToOU {
			if slices.Contains(g.ExcludedOUIDs, hop) {
				excluded = true
				break
			}
		}
		if !excluded {
			return true, g
		}
	}
	return false, nil
}

// isImmediateChildOf reports whether ouID's direct parent is parentOUID. A Root OU (no parent) is
// never an immediate child of anything.
func (s *service) isImmediateChildOf(ctx context.Context, ouID, parentOUID string) (bool, *tidcommon.ServiceError) {
	ancestors, svcErr := s.ouHierarchyResolver.GetAncestorOUIDs(ctx, ouID)
	if svcErr != nil {
		return false, svcErr
	}
	if len(ancestors) == 0 {
		return false, nil
	}
	return ancestors[0] == parentOUID, nil
}

// isRootOU reports whether ouID has no parent.
func (s *service) isRootOU(ctx context.Context, ouID string) (bool, *tidcommon.ServiceError) {
	ancestors, svcErr := s.ouHierarchyResolver.GetAncestorOUIDs(ctx, ouID)
	if svcErr != nil {
		return false, svcErr
	}
	return len(ancestors) == 0, nil
}

// resolveOwnRootOUID returns ouID's own tree's root: ouID itself if it is already a root (so
// callers can test "is ouID a root" via result == ouID, without a second lookup), else the
// topmost ancestor in its chain. GetAncestorOUIDs is nearest-first (parent...root), so the root is
// always the last element of a non-empty result.
func (s *service) resolveOwnRootOUID(ctx context.Context, ouID string) (string, *tidcommon.ServiceError) {
	ancestors, svcErr := s.ouHierarchyResolver.GetAncestorOUIDs(ctx, ouID)
	if svcErr != nil {
		return "", svcErr
	}
	if len(ancestors) == 0 {
		return ouID, nil
	}
	return ancestors[len(ancestors)-1], nil
}

// isWithinSubtree reports whether ouID is anchorOUID itself or one of its descendants.
func (s *service) isWithinSubtree(ctx context.Context, ouID, anchorOUID string) (bool, *tidcommon.ServiceError) {
	if ouID == anchorOUID {
		return true, nil
	}
	ancestors, svcErr := s.ouHierarchyResolver.GetAncestorOUIDs(ctx, ouID)
	if svcErr != nil {
		return false, svcErr
	}
	return slices.Contains(ancestors, anchorOUID), nil
}

// createGrant generates an id and persists a new grant.
func (s *service) createGrant(
	ctx context.Context,
	resourceType ResourceType, resourceID, owningOUID string,
	stage Stage, targetScope TargetScope, targetOUID, parentGrantID string,
	excludedOUIDs, editableFields []string,
) (*Grant, *tidcommon.ServiceError) {
	id, err := utils.GenerateUUIDv7()
	if err != nil {
		s.logger.Error(ctx, "Failed to generate grant id", log.Error(err))
		return nil, &tidcommon.InternalServerError
	}
	grant := Grant{
		ID:             id,
		ResourceType:   resourceType,
		ResourceID:     resourceID,
		OwningOUID:     owningOUID,
		Stage:          stage,
		TargetScope:    targetScope,
		TargetOUID:     targetOUID,
		ParentGrantID:  parentGrantID,
		ExcludedOUIDs:  excludedOUIDs,
		EditableFields: editableFields,
	}
	// A grant declared by a declarative resource file is held in memory for the lifetime of the
	// process rather than persisted: the file owns it, exactly as it owns the resource itself,
	// which is likewise never written to the database.
	if isDeclarativeLoad(ctx) && s.declarativeStore != nil {
		s.declarativeStore.Seed(grant)
		return &grant, nil
	}

	if err := s.store.CreateGrant(ctx, grant); err != nil {
		s.logger.Error(ctx, "Failed to create grant", log.Error(err))
		return nil, &tidcommon.InternalServerError
	}
	return &grant, nil
}
