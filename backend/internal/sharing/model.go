// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

// Package sharing provides a generalized, resource-type-agnostic framework for sharing a
// resource from its owning organization unit (OU) to other OUs, and for resolving the
// per-OU-editable ("templated") parts of that resource. A resource type is onboarded by
// registering a ResourceTypeDeclaration; the sharing engine, storage, and templated-field
// editability resolution are otherwise identical for every resource type.
//
// Sharing is a single operation, Share(ctx, resourceType, resourceID, owningOUID, actingOUID,
// policy), with two target-scope modes selected by which fields of SharePolicy are populated:
//
//   - Root-targeting (AllRoots/RootOUIDs, optionally ExcludedRootOUIDs): the only mode that
//     crosses from the owner's own subtree into a different one — either a foreign Root's tree, or
//     (when the owner is not itself a Root) the owner's own Root, as a deliberate step to then fan
//     out sideways within that tree via a children-targeting call. Only actingOUID == owningOUID
//     may use this mode: a sharee has no standing to name an arbitrary Root as a target.
//
//   - Children-targeting (AllChildren/OUIDs, optionally ExcludedOUIDs): distributes within a
//     subtree actingOUID already sits at the top of. The resource's owning OU is always trivially
//     visible to itself, so an owner (Root or not) can use this mode directly, in one call, with
//     no preceding root-targeting call — this is how "share this role with my own children" is a
//     single step when the owner already is the top of the subtree being distributed into. Any
//     other actingOUID must currently be visible (owner, or via a prior Share call in either mode)
//     before it may distribute further — a sharee resharing what was shared to it is not a
//     different operation or a looser check, it is this exact same call and the exact same
//     visibility rule. Policy is "all children (including future children)", "all children except
//     some", or "selected immediate children" — an explicit list may only name actingOUID's own
//     direct children (see TargetScopeOU); reaching a grandchild selectively requires that child
//     to issue its own Share call in turn, so access delegates one hop at a time and is never
//     implicitly deep. "All children" has no such restriction: it is a single dynamic grant
//     covering the entire subtree, any depth, forever (subject to its exclusion list).
//
// Every grant persisted by either mode still records which mode produced it: Stage is StageShare
// when the resource's own owning OU is the one issuing the grant (whichever target-scope mode —
// root-targeting is always owner-only, but an owner may also use children-targeting directly), and
// StageReshare when a previously-visible non-owner OU redistributes further. For children-targeting
// grants issued by a non-owner actingOUID, the grant also records which grant established that OU's
// own access (ParentGrantID, for lineage and cascade revocation) — merging the two modes into one
// exported operation does not change the underlying grant model or its bookkeeping at all.
//
// "All future children" grants are not snapshotted. TargetOUID on such a grant holds the anchor
// OU, and subtree membership is evaluated dynamically at read time by walking the target OU's
// ancestor chain up to that anchor (see service.go), so a newly created child OU is in scope
// immediately with no backfill and no per-request tree walk beyond a single ancestor lookup. An
// "except" list works the same way: excluding an OU excludes its entire (current and future)
// subtree too, checked via the same ancestor chain.
//
// Visibility is resolved by walking the OU chain from the resource's tree root down to the OU in
// question and confirming every hop is backed by a valid grant (or the owner's own unconditional
// access, wherever it sits in that chain) — a child is never visible merely because some row
// happens to name it; its parent must be visible too, and the parent must have actually granted
// it (see evaluateChainVisibility in service.go). This is what makes a multi-hop delegation chain
// (Root -> child -> grandchild, each an explicit, independent children-targeting call) behave
// correctly when an intermediate link is missing or excluded: the break cuts off everything below
// it.
package sharing

import (
	"context"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
)

// ResourceType identifies a resource type registered with the sharing framework (e.g. "role").
type ResourceType string

// Stage distinguishes the two sharing modes a Share call can produce a grant under.
type Stage string

const (
	// StageShare represents the root-targeting mode: owning OU -> Root(s).
	StageShare Stage = "share"
	// StageReshare represents the children-targeting mode: an OU -> its own subtree.
	StageReshare Stage = "reshare"
)

// TargetScope identifies the breadth of a grant's target: a single named OU, or an "all" scope
// (optionally narrowed by an exclusion list — see Grant.ExcludedOUIDs).
type TargetScope string

const (
	// TargetScopeAllRoots is a share-stage grant visible to every Root OU, except any listed in
	// ExcludedOUIDs (and their subtrees).
	TargetScopeAllRoots TargetScope = "all_roots"
	// TargetScopeRoot is a share-stage grant visible to one specific Root OU (TargetOUID).
	TargetScopeRoot TargetScope = "root"
	// TargetScopeAllChildren is a reshare-stage grant visible to every current and future OU in
	// the subtree anchored at TargetOUID (the OU that issued the children-targeting call — the
	// resource's owner itself, or any OU that was itself made visible by an earlier Share call),
	// except any listed in ExcludedOUIDs (and their subtrees). Unlike TargetScopeOU, this reaches
	// any depth in one grant with no further hops required.
	TargetScopeAllChildren TargetScope = "all_children"
	// TargetScopeOU is a reshare-stage grant visible to one specific OU (TargetOUID), which must
	// be the issuing OU's own direct child — never a grandchild or deeper. Reaching further down
	// requires that child to issue its own children-targeting call; access delegates one hop at a
	// time.
	TargetScopeOU TargetScope = "ou"
	// TargetScopeOUSubtree is TargetScopeOU plus everything beneath it: visible to TargetOUID —
	// which, exactly as for TargetScopeOU, must be the issuing OU's own direct child — and to every
	// current and future OU in that child's own subtree, at any depth, except any listed in
	// ExcludedOUIDs (and their subtrees).
	//
	// This is the "one named branch, whole" scope. TargetScopeAllChildren can only ever anchor at
	// the OU that issued it, so an OU wanting to hand one of its children a resource for that
	// child's entire branch could otherwise only name the child (TargetScopeOU) and wait for the
	// child to redistribute in a second call it does not control. The one-hop delegation rule is
	// still intact: the issuer may only name a direct child, and what it delegates is that child's
	// own subtree, which is precisely what the child could have granted for itself.
	TargetScopeOUSubtree TargetScope = "ou_subtree"
)

// Grant is one row of the sharing graph: either a share-stage grant (owning OU -> Root(s))
// or a reshare-stage grant (an OU -> its own subtree).
type Grant struct {
	ID            string
	ResourceType  ResourceType
	ResourceID    string
	OwningOUID    string
	Stage         Stage
	TargetScope   TargetScope
	TargetOUID    string // empty for TargetScopeAllRoots
	ParentGrantID string // empty for share-stage grants; set for reshare-stage grants (lineage/audit only)
	// ExcludedOUIDs carves specific OUs (and their entire subtrees) out of an otherwise-blanket
	// TargetScopeAllRoots or TargetScopeAllChildren grant, e.g. "share to all Roots except this
	// one". Always empty for the explicit TargetScopeRoot/TargetScopeOU scopes.
	ExcludedOUIDs []string
	// EditableFields is the materialized set of templated field keys editable through this grant:
	// every declared field, for a grant issued by the resource's own owning OU (StageShare), unless
	// the Share call named an explicit subset; exactly the acting OU's own current editable set,
	// for a reshare (StageReshare), unless the call named an explicit subset of that set — a
	// reshare can only narrow this set relative to its own, never widen it. Always a concrete,
	// non-ambiguous list fixed at grant creation time; never re-interpreted later.
	EditableFields []string
}

// GrantPage is one page of a resource's grants alongside the total number available,
// so a caller can build pagination links without a second round trip.
type GrantPage struct {
	Grants       []Grant
	TotalResults int
}

// ReplayableGrant pairs the organization unit that issued a grant with the SharePolicy that
// recreates it. See ServiceInterface.ExportGrants.
type ReplayableGrant struct {
	ActingOUID string
	Policy     SharePolicy
}

// SharePolicy describes the target scope of a Share call. Exactly one of the two modes below must
// be selected: root-targeting (AllRoots or a non-empty RootOUIDs) or children-targeting
// (AllChildren or a non-empty OUIDs) — see the package doc comment for what each mode means and
// who may use it.
type SharePolicy struct {
	// AllRoots shares the resource to every current and future Root OU. Root-targeting mode;
	// only valid when the caller is the resource's owning OU.
	AllRoots bool
	// RootOUIDs is the explicit set of Root OUs to share to. Ignored when AllRoots is true.
	// Root-targeting mode; only valid when the caller is the resource's owning OU.
	RootOUIDs []string
	// ExcludedRootOUIDs carves these Root OUs (and their subtrees) out of the AllRoots grant.
	// Each must itself be a Root OU. Ignored unless AllRoots is true.
	ExcludedRootOUIDs []string
	// AllChildren shares the resource to every OU, current and future, in the caller's own
	// subtree, any depth, in one grant. Children-targeting mode; valid for any caller currently
	// visible for the resource.
	AllChildren bool
	// OUIDs is the explicit set of OUs to share to. Each must be a direct child of the caller —
	// reaching a grandchild selectively requires that child to share again in turn. Ignored when
	// AllChildren is true. Children-targeting mode; valid for any caller currently visible for the
	// resource.
	OUIDs []string
	// SubtreeOUIDs is the explicit set of OUs to share to *together with their own subtrees*, at
	// any depth. Each must be a direct child of the caller, exactly as for OUIDs — what differs is
	// only how far the grant reaches below that child. Use this to hand one named branch over
	// whole, where AllChildren would hand over every branch and OUIDs only the child itself.
	// Ignored when AllChildren is true. Children-targeting mode; may be combined with OUIDs to give
	// some children the subtree and others only themselves.
	SubtreeOUIDs []string
	// ExcludedOUIDs carves these OUs (and their subtrees) out of an AllChildren grant, or out of
	// any SubtreeOUIDs grant whose own subtree contains them. Each must be the caller itself or
	// within its subtree. Ignored when neither AllChildren nor SubtreeOUIDs is set.
	ExcludedOUIDs []string
	// EditableFields names the templated fields made editable through this grant. Empty means
	// "everything": every field the resource type declares, when actingOUID is the resource's own
	// owning OU; exactly actingOUID's own current editable set, when actingOUID is a sharee
	// reshare — a reshare may only narrow this set relative to its own, never widen it (an explicit
	// list naming a field actingOUID cannot itself currently edit is rejected).
	EditableFields []string
}

// TemplatedFieldDeclaration describes one templated (per-OU-adjustable) field of a resource type.
type TemplatedFieldDeclaration struct {
	// Key is the field's identifier, e.g. "assignments.user".
	Key string
	// FallbackKey, when non-empty, names a coarser sibling field consulted when a grant's
	// EditableFields has no entry for Key itself. This lets an owner make one blanket field (e.g.
	// "assignments") editable, implicitly covering a whole family of more specific fields (e.g.
	// "assignments.user", "assignments.group", ...) without naming each one individually, while a
	// caller who does want finer control can still name Key alone.
	// FallbackKey must itself be a declared field of the same resource type; leave empty for a
	// field with no coarser fallback (e.g. the blanket field itself).
	FallbackKey string
}

// ResourceTypeDeclaration is implemented by each resource type onboarded onto the sharing
// framework (e.g. role). It declares the type's templated fields; core fields need no
// declaration here since they are never touched by the sharing/templated-config machinery —
// they are always resolved from the owning OU by the resource type's own service.
type ResourceTypeDeclaration interface {
	// ResourceType returns the type's identifier, used as the RESOURCE_TYPE column value.
	ResourceType() ResourceType
	// TemplatedFields returns the type's templated field declarations.
	TemplatedFields() []TemplatedFieldDeclaration
}

// SharingHooks is an optional capability a ResourceTypeDeclaration may implement (checked via
// type assertion, mirroring resourcedependency.CascadeDeleter/UpdateValidator) to react to a
// sharee OU losing access. OnUnshare is called once per OU whose access to resourceID has just
// been revoked, so the resource type can clean up any per-OU state it keeps outside the generic
// overlay tables (e.g. role assignments held in ROLE_ASSIGNMENT).
type SharingHooks interface {
	OnUnshare(ctx context.Context, resourceID, ouID string) error
}

// DeletionOwnershipError is an optional capability a ResourceTypeDeclaration may implement
// (checked via type assertion, mirroring SharingHooks) to supply a resource-type-specific error
// when a non-owning, non-root caller attempts to delete a resource of that type. Deletion reads
// naturally as a distinct, resource-type-meaningful violation ("this role/agent/whatever cannot
// be deleted by this organization unit") rather than a generic core-config edit, so
// RequireOwnershipForDeletion returns this in place of ErrorCoreConfigOwnerOnly when a resource
// type implements it; types that don't implement it get the generic error unchanged.
type DeletionOwnershipError interface {
	ErrorResourceDeletionRestrictedToOwner() *tidcommon.ServiceError
}
