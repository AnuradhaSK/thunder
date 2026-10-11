// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

import {describe, it, expect} from 'vitest';
import type {SharingPolicy, SharingTarget} from '../../models/sharing-policy';
import planSharingPolicySave, {canEditSharingTargetsInPlace, haveSameSharingTargets} from '../planSharingPolicySave';

const policyWith = (targets: SharingTarget[]): SharingPolicy => ({id: 'p1', stage: 'share', version: 4, targets});

describe('planSharingPolicySave', () => {
  it('does nothing when an unshared resource stays unshared', () => {
    expect(planSharingPolicySave(undefined, [])).toEqual({type: 'none'});
  });

  it('creates a policy for a resource that is not shared yet', () => {
    const targets: SharingTarget[] = [{scope: 'allChildren'}];

    expect(planSharingPolicySave(undefined, targets)).toEqual({type: 'create', targets});
  });

  it('deletes the policy when nothing is shared any more', () => {
    expect(planSharingPolicySave(policyWith([{scope: 'allChildren'}]), [])).toEqual({type: 'delete', policyId: 'p1'});
  });

  it('does nothing when the targets are unchanged, in any order', () => {
    const current = policyWith([
      {scope: 'allChildren', excludedOuIds: ['b', 'a']},
      {scope: 'root', ouId: 'northwind'},
    ]);

    expect(
      planSharingPolicySave(current, [
        {scope: 'root', ouId: 'northwind'},
        {scope: 'allChildren', excludedOuIds: ['a', 'b']},
      ]),
    ).toEqual({type: 'none'});
  });

  it('edits in place when only exclusions and selective targets change', () => {
    const targets: SharingTarget[] = [
      {scope: 'allRoots', excludedOuIds: ['contoso']},
      {scope: 'child', ouId: 'retail'},
    ];

    expect(planSharingPolicySave(policyWith([{scope: 'allRoots'}]), targets)).toEqual({
      type: 'update',
      policyId: 'p1',
      version: 4,
      targets,
    });
  });

  it('replaces the policy when a blanket target is added or dropped', () => {
    const targets: SharingTarget[] = [{scope: 'allChildren'}];

    expect(planSharingPolicySave(policyWith([{scope: 'child', ouId: 'retail'}]), targets)).toEqual({
      type: 'replace',
      policyId: 'p1',
      targets,
    });
  });
});

describe('haveSameSharingTargets', () => {
  it('tells apart targets that reach different units', () => {
    expect(haveSameSharingTargets([{scope: 'child', ouId: 'a'}], [{scope: 'childSubtree', ouId: 'a'}])).toBe(false);
  });
});

describe('canEditSharingTargetsInPlace', () => {
  it('allows edits that keep the same blanket scopes', () => {
    expect(canEditSharingTargetsInPlace([{scope: 'allOus'}], [{scope: 'allOus', excludedOuIds: ['x']}])).toBe(true);
  });

  it('refuses edits that swap a blanket scope', () => {
    expect(canEditSharingTargetsInPlace([{scope: 'allOus'}], [{scope: 'allChildren'}])).toBe(false);
  });
});
