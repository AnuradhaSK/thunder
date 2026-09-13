// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package application

import (
	"context"
	"fmt"

	"github.com/thunder-id/thunderid/internal/sharing"
)

// applicationSharingType is the sharing-framework identifier for applications. Granting an
// application to an organization unit does not make the application visible or editable there: it
// only permits that organization unit to be named as the accessing OU on a token request
// (/ou/{ouId}/oauth2/token). A machine-to-machine service therefore stays invisible inside the
// organizations it serves while still being able to obtain tokens scoped to them.
const applicationSharingType sharing.ResourceType = "application"

// applicationTypeDeclaration implements sharing.ResourceTypeDeclaration for applications.
//
// It declares no templated fields. An application's configuration (its credentials, flows, allowed
// grant types) is global to the application, not per-organization-unit state layered on top of a
// shared definition. What varies per organization unit is which permissions the resulting token may
// carry, and that is resolved from the resource-server grants of the accessing OU at token issuance
// rather than stored against the application.
//
// It also implements no SharingHooks: nothing is persisted per (application, OU), so an OU losing
// access has nothing to clean up. Revoking the grant is sufficient on its own, because the grant is
// consulted on every token request rather than snapshotted into anything.
type applicationTypeDeclaration struct{}

func newApplicationTypeDeclaration() sharing.ResourceTypeDeclaration {
	return &applicationTypeDeclaration{}
}

// ResourceType returns the sharing-framework identifier for applications.
func (d *applicationTypeDeclaration) ResourceType() sharing.ResourceType {
	return applicationSharingType
}

// TemplatedFields returns no fields; see the type doc for why an application has none.
func (d *applicationTypeDeclaration) TemplatedFields() []sharing.TemplatedFieldDeclaration {
	return []sharing.TemplatedFieldDeclaration{}
}

// ShareRequest is one declaratively-declared grant of an application to other organization units.
// It mirrors the target-scope shape used by role and resource-server grants, minus the fields that
// only make sense for a tree-shaped resource: an application has no descendants to cascade to, and
// declares no templated fields, so there is nothing to exclude from a cascade and nothing to make
// editable.
type ShareRequest struct {
	// OUID is the organization unit performing this share. Optional; defaults to the application's
	// own owning organization unit when omitted.
	OUID string `json:"ouId,omitempty" yaml:"ouId,omitempty"`
	// AllOUs grants the application to every organization unit in the deployment, at every depth,
	// current and future. This is the "service available to the whole tenant base" case.
	AllOUs    bool     `json:"allOus,omitempty"    yaml:"allOus,omitempty"`
	AllRoots  bool     `json:"allRoots,omitempty"  yaml:"allRoots,omitempty"`
	RootOUIDs []string `json:"rootOuIds,omitempty" yaml:"rootOuIds,omitempty"`
	// ExcludedRootOUIDs carves these Root OUs (and their subtrees) out of an AllRoots grant.
	ExcludedRootOUIDs []string `json:"excludedRootOuIds,omitempty" yaml:"excludedRootOuIds,omitempty"`
	AllChildren       bool     `json:"allChildren,omitempty"       yaml:"allChildren,omitempty"`
	// OUIDs, when set, must each be a direct child of ouId.
	OUIDs []string `json:"ouIds,omitempty" yaml:"ouIds,omitempty"`
	// ExcludedOUIDs carves these OUs (and their subtrees) out of an AllChildren or AllOUs grant.
	ExcludedOUIDs []string `json:"excludedOuIds,omitempty" yaml:"excludedOuIds,omitempty"`
}

// ToSharePolicy converts req's target-scope fields into the sharing.SharePolicy Share() expects.
func (req ShareRequest) ToSharePolicy() sharing.SharePolicy {
	return sharing.SharePolicy{
		AllOUs:            req.AllOUs,
		AllRoots:          req.AllRoots,
		RootOUIDs:         req.RootOUIDs,
		ExcludedRootOUIDs: req.ExcludedRootOUIDs,
		AllChildren:       req.AllChildren,
		OUIDs:             req.OUIDs,
		ExcludedOUIDs:     req.ExcludedOUIDs,
	}
}

// ApplicationSharingResourceType exposes the application sharing-framework identifier to callers
// outside this package (the declarative importer) without exporting the declaration itself.
const ApplicationSharingResourceType = applicationSharingType

// applyPendingAppGrants replays each declaratively-declared application grant through the normal
// Share() API, so a declared grant goes through exactly the eligibility checks a programmatic one
// would. Already-present grants are skipped: declarative loading runs on every startup and Share()
// does not dedupe, so replaying unconditionally would append a duplicate row each time.
func applyPendingAppGrants(pending []pendingAppGrant, sharingService sharing.ServiceInterface) error {
	if len(pending) == 0 || sharingService == nil {
		return nil
	}
	ctx := context.Background()

	for _, p := range pending {
		existing, svcErr := sharingService.ExportGrants(ctx, applicationSharingType, p.appID)
		if svcErr != nil {
			return fmt.Errorf("application '%s': failed to read existing grants: %s", p.appID, svcErr.Code)
		}
		for _, grant := range p.grants {
			actingOUID := grant.OUID
			if actingOUID == "" {
				actingOUID = p.ownerOU
			}
			policy := grant.ToSharePolicy()
			if appGrantPresent(existing, actingOUID, policy) {
				continue
			}
			if _, svcErr := sharingService.Share(
				ctx, applicationSharingType, p.appID, p.ownerOU, actingOUID, policy,
			); svcErr != nil {
				return fmt.Errorf("application '%s': failed to apply declarative grant: %s", p.appID, svcErr.Code)
			}
		}
	}
	return nil
}

// appGrantPresent reports whether existing already holds a grant equivalent to the one
// (actingOUID, policy) would create. Slice fields are compared as sets, since neither the grant
// store nor ExportGrants promises to preserve declared order.
func appGrantPresent(
	existing []sharing.ReplayableGrant, actingOUID string, policy sharing.SharePolicy,
) bool {
	for _, e := range existing {
		if e.ActingOUID == actingOUID && sharePoliciesEquivalent(e.Policy, policy) {
			return true
		}
	}
	return false
}

func sharePoliciesEquivalent(a, b sharing.SharePolicy) bool {
	return a.AllOUs == b.AllOUs &&
		a.AllRoots == b.AllRoots &&
		a.AllChildren == b.AllChildren &&
		sameStringSet(a.RootOUIDs, b.RootOUIDs) &&
		sameStringSet(a.OUIDs, b.OUIDs) &&
		sameStringSet(a.ExcludedRootOUIDs, b.ExcludedRootOUIDs) &&
		sameStringSet(a.ExcludedOUIDs, b.ExcludedOUIDs)
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
		if seen[v] < 0 {
			return false
		}
	}
	return true
}
