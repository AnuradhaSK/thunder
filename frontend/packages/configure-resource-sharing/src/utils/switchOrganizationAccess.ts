// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

import draftToSharingTargets from './draftToSharingTargets';
import {canEditSharingTargetsInPlace} from './planSharingPolicySave';
import type {AccessSwitch, ClearedAccessItem, OrganizationAccessDraft} from '../models/organization-access';
import type {SharingPolicy} from '../models/sharing-policy';

function clearChildUnits(draft: OrganizationAccessDraft): void {
  draft.childUnitsAccess = 'none';
  draft.childUnitExclusions = [];
  draft.childUnits = [];
}

function clearOtherTrees(draft: OrganizationAccessDraft): void {
  draft.otherTreesAccess = 'none';
  draft.trees = [];
  draft.everyTreeExclusions = [];
}

/**
 * Applies a switch between Organization Access choices and reports what it clears.
 *
 * Each choice owns its own settings, so they never carry over: leaving `all` child units clears
 * its exceptions, leaving `selected` clears the granted units, and leaving the `chosen` scope clears
 * both sections.
 *
 * "Every tree" can only be kept by editing the saved policy in place. When the switch changes which
 * blanket targets the policy holds, saving has to replace the policy, and a replacement cannot carry
 * a deployment-wide target, so "Every tree" is dropped with it.
 *
 * @param draft - The draft before the switch
 * @param field - The choice being switched
 * @param to - The new value of that choice
 * @param saved - The policy as last read, against which an in-place edit is judged
 * @returns The draft after the switch and what it cleared
 */
export default function switchOrganizationAccess(
  draft: OrganizationAccessDraft,
  field: AccessSwitch['field'],
  to: AccessSwitch['to'],
  saved: SharingPolicy | undefined,
): AccessSwitch {
  const next: OrganizationAccessDraft = {...draft, [field]: to};

  if (field === 'scope') {
    if (draft.scope === 'everyUnit') next.everyUnitExclusions = [];
    if (draft.scope === 'chosen' || to !== 'chosen') {
      clearChildUnits(next);
      clearOtherTrees(next);
    }
  } else if (field === 'childUnitsAccess') {
    if (draft.childUnitsAccess === 'all') next.childUnitExclusions = [];
    if (draft.childUnitsAccess === 'selected') next.childUnits = [];
  } else {
    if (draft.otherTreesAccess === 'selected') next.trees = [];
    if (draft.otherTreesAccess === 'every') next.everyTreeExclusions = [];
  }

  const savedTargets = saved?.targets ?? [];
  if (next.otherTreesAccess === 'every' && !canEditSharingTargetsInPlace(savedTargets, draftToSharingTargets(next))) {
    clearOtherTrees(next);
  }

  const cleared: ClearedAccessItem[] = [];
  const dropped = (before: string[], after: string[]): string[] => before.filter((id) => !after.includes(id));

  const losesEveryUnit = draft.scope === 'everyUnit' && next.scope !== 'everyUnit';
  const losesEveryTree = draft.otherTreesAccess === 'every' && next.otherTreesAccess !== 'every';

  if (losesEveryUnit) {
    cleared.push({kind: 'everyUnit', ouIds: [...draft.everyUnitExclusions]});
  }
  const droppedExclusions = dropped(draft.childUnitExclusions, next.childUnitExclusions);
  if (droppedExclusions.length > 0) {
    cleared.push({kind: 'childUnitExclusions', ouIds: droppedExclusions});
  }
  const droppedUnits = dropped(
    draft.childUnits.map((unit) => unit.ouId),
    next.childUnits.map((unit) => unit.ouId),
  );
  if (droppedUnits.length > 0) {
    cleared.push({kind: 'childUnits', ouIds: droppedUnits});
  }
  if (losesEveryTree) {
    cleared.push({kind: 'everyTree', ouIds: [...draft.everyTreeExclusions]});
  }
  const droppedTrees = dropped(draft.trees, next.trees);
  if (droppedTrees.length > 0) {
    cleared.push({kind: 'trees', ouIds: droppedTrees});
  }

  return {field, to, next, cleared, losesEveryUnit, losesEveryTree};
}
