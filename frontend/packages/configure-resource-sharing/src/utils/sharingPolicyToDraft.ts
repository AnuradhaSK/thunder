// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

import type {OrganizationAccessDraft} from '../models/organization-access';
import type {SharingPolicy} from '../models/sharing-policy';

/**
 * The draft of a resource no policy shares: only its owner can use it.
 */
export const EMPTY_ORGANIZATION_ACCESS_DRAFT: OrganizationAccessDraft = {
  scope: 'owner',
  childUnitsAccess: 'none',
  childUnitExclusions: [],
  childUnits: [],
  everyUnitExclusions: [],
  otherTreesAccess: 'none',
  trees: [],
  everyTreeExclusions: [],
};

/**
 * Reads a resource's owner-issued sharing policy into the form the Organization Access screen edits.
 *
 * Child units and other trees are read independently, so a policy that reaches only other trees
 * reads as no child units beside the trees it names.
 *
 * @param policy - The owner's policy, or `undefined` when the resource is not shared
 * @returns The draft the policy amounts to
 */
export default function sharingPolicyToDraft(policy: SharingPolicy | undefined): OrganizationAccessDraft {
  const draft: OrganizationAccessDraft = {
    ...EMPTY_ORGANIZATION_ACCESS_DRAFT,
    childUnitExclusions: [],
    childUnits: [],
    everyUnitExclusions: [],
    trees: [],
    everyTreeExclusions: [],
  };

  if (!policy || policy.targets.length === 0) {
    return draft;
  }

  draft.scope = 'chosen';

  policy.targets.forEach((target) => {
    const excluded = target.excludedOuIds ?? [];

    switch (target.scope) {
      case 'allOus':
        draft.scope = 'everyUnit';
        draft.everyUnitExclusions = [...excluded];
        break;
      case 'allChildren':
        draft.childUnitsAccess = 'all';
        draft.childUnitExclusions = [...excluded];
        break;
      case 'child':
      case 'childSubtree':
        if (target.ouId) {
          draft.childUnits.push({ouId: target.ouId, reach: target.scope === 'child' ? 'unit' : 'subtree'});
          if (draft.childUnitsAccess === 'none') draft.childUnitsAccess = 'selected';
        }
        break;
      case 'root':
        if (target.ouId) {
          draft.trees.push(target.ouId);
          if (draft.otherTreesAccess === 'none') draft.otherTreesAccess = 'selected';
        }
        break;
      case 'allRoots':
        draft.otherTreesAccess = 'every';
        draft.everyTreeExclusions = [...excluded];
        break;
      default:
        break;
    }
  });

  return draft;
}
