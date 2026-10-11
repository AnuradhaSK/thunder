// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

import type {OrganizationAccessDraft} from '../models/organization-access';
import type {SharingTarget} from '../models/sharing-policy';

function withExclusions(target: SharingTarget, excluded: string[]): SharingTarget {
  return excluded.length > 0 ? {...target, excludedOuIds: [...excluded]} : target;
}

/**
 * Writes an Organization Access draft as the targets of a sharing policy.
 *
 * An empty result means the resource is not shared at all, so its policy has to go rather than be
 * written with no targets. That is the case for the `owner` scope, and for a `chosen` scope whose
 * child-unit and other-tree sections grant nothing.
 *
 * @param draft - The draft to write
 * @returns The policy targets, in a stable order
 */
export default function draftToSharingTargets(draft: OrganizationAccessDraft): SharingTarget[] {
  if (draft.scope === 'owner') {
    return [];
  }
  if (draft.scope === 'everyUnit') {
    return [withExclusions({scope: 'allOus'}, draft.everyUnitExclusions)];
  }

  const targets: SharingTarget[] = [];

  if (draft.childUnitsAccess === 'all') {
    targets.push(withExclusions({scope: 'allChildren'}, draft.childUnitExclusions));
  }
  if (draft.childUnitsAccess === 'selected') {
    draft.childUnits.forEach((unit) => {
      targets.push({scope: unit.reach === 'unit' ? 'child' : 'childSubtree', ouId: unit.ouId});
    });
  }

  if (draft.otherTreesAccess === 'every') {
    targets.push(withExclusions({scope: 'allRoots'}, draft.everyTreeExclusions));
  }
  if (draft.otherTreesAccess === 'selected') {
    draft.trees.forEach((ouId) => targets.push({scope: 'root', ouId}));
  }

  return targets;
}
