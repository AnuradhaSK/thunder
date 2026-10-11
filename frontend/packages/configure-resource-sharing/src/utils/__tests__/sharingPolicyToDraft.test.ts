// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

import {describe, it, expect} from 'vitest';
import type {SharingPolicy, SharingTarget} from '../../models/sharing-policy';
import sharingPolicyToDraft, {EMPTY_ORGANIZATION_ACCESS_DRAFT} from '../sharingPolicyToDraft';

const policyWith = (targets: SharingTarget[]): SharingPolicy => ({id: 'p1', stage: 'share', version: 1, targets});

describe('sharingPolicyToDraft', () => {
  it('reads a missing policy as owner-only access', () => {
    expect(sharingPolicyToDraft(undefined)).toEqual(EMPTY_ORGANIZATION_ACCESS_DRAFT);
  });

  it('reads allChildren with its exclusions as all child units', () => {
    const draft = sharingPolicyToDraft(policyWith([{scope: 'allChildren', excludedOuIds: ['trials']}]));

    expect(draft.scope).toBe('chosen');
    expect(draft.childUnitsAccess).toBe('all');
    expect(draft.childUnitExclusions).toEqual(['trials']);
    expect(draft.otherTreesAccess).toBe('none');
  });

  it('reads child and childSubtree targets as selected units with their reach', () => {
    const draft = sharingPolicyToDraft(
      policyWith([
        {scope: 'child', ouId: 'wholesale'},
        {scope: 'childSubtree', ouId: 'retail'},
      ]),
    );

    expect(draft.childUnitsAccess).toBe('selected');
    expect(draft.childUnits).toEqual([
      {ouId: 'wholesale', reach: 'unit'},
      {ouId: 'retail', reach: 'subtree'},
    ]);
  });

  it('reads a policy reaching only other trees as no child units beside selected trees', () => {
    const draft = sharingPolicyToDraft(policyWith([{scope: 'root', ouId: 'northwind'}]));

    expect(draft.scope).toBe('chosen');
    expect(draft.childUnitsAccess).toBe('none');
    expect(draft.otherTreesAccess).toBe('selected');
    expect(draft.trees).toEqual(['northwind']);
  });

  it('reads allOus as the every organization unit scope', () => {
    const draft = sharingPolicyToDraft(policyWith([{scope: 'allOus', excludedOuIds: ['sandbox']}]));

    expect(draft.scope).toBe('everyUnit');
    expect(draft.everyUnitExclusions).toEqual(['sandbox']);
  });

  it('reads allRoots as every tree, independent of the child units', () => {
    const draft = sharingPolicyToDraft(
      policyWith([{scope: 'allChildren'}, {scope: 'allRoots', excludedOuIds: ['contoso']}]),
    );

    expect(draft.childUnitsAccess).toBe('all');
    expect(draft.otherTreesAccess).toBe('every');
    expect(draft.everyTreeExclusions).toEqual(['contoso']);
  });

  it('does not share list instances between drafts', () => {
    const first = sharingPolicyToDraft(undefined);
    first.trees.push('x');

    expect(sharingPolicyToDraft(undefined).trees).toEqual([]);
  });
});
