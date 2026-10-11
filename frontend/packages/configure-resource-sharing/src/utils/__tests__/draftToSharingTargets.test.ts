// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

import {describe, it, expect} from 'vitest';
import type {OrganizationAccessDraft} from '../../models/organization-access';
import type {SharingPolicy} from '../../models/sharing-policy';
import draftToSharingTargets from '../draftToSharingTargets';
import sharingPolicyToDraft, {EMPTY_ORGANIZATION_ACCESS_DRAFT} from '../sharingPolicyToDraft';

const chosen = (overrides: Partial<OrganizationAccessDraft>): OrganizationAccessDraft => ({
  ...EMPTY_ORGANIZATION_ACCESS_DRAFT,
  scope: 'chosen',
  ...overrides,
});

describe('draftToSharingTargets', () => {
  it('writes owner-only access as no targets', () => {
    expect(draftToSharingTargets({...EMPTY_ORGANIZATION_ACCESS_DRAFT, trees: ['northwind']})).toEqual([]);
  });

  it('writes chosen units with nothing granted as no targets', () => {
    expect(draftToSharingTargets(chosen({}))).toEqual([]);
  });

  it('writes all child units with exclusions and selected trees', () => {
    expect(
      draftToSharingTargets(
        chosen({
          childUnitsAccess: 'all',
          childUnitExclusions: ['trials'],
          otherTreesAccess: 'selected',
          trees: ['northwind'],
        }),
      ),
    ).toEqual([
      {scope: 'allChildren', excludedOuIds: ['trials']},
      {scope: 'root', ouId: 'northwind'},
    ]);
  });

  it('omits empty exclusions', () => {
    expect(draftToSharingTargets(chosen({childUnitsAccess: 'all'}))).toEqual([{scope: 'allChildren'}]);
  });

  it('writes selected units by their reach', () => {
    expect(
      draftToSharingTargets(
        chosen({
          childUnitsAccess: 'selected',
          childUnits: [
            {ouId: 'wholesale', reach: 'unit'},
            {ouId: 'retail', reach: 'subtree'},
          ],
        }),
      ),
    ).toEqual([
      {scope: 'child', ouId: 'wholesale'},
      {scope: 'childSubtree', ouId: 'retail'},
    ]);
  });

  it('writes other trees on their own, with no child units', () => {
    expect(draftToSharingTargets(chosen({otherTreesAccess: 'selected', trees: ['northwind']}))).toEqual([
      {scope: 'root', ouId: 'northwind'},
    ]);
  });

  it('writes every tree instead of the selected trees', () => {
    expect(
      draftToSharingTargets(
        chosen({otherTreesAccess: 'every', trees: ['northwind'], everyTreeExclusions: ['contoso']}),
      ),
    ).toEqual([{scope: 'allRoots', excludedOuIds: ['contoso']}]);
  });

  it('writes the every organization unit scope alone', () => {
    expect(
      draftToSharingTargets({
        ...EMPTY_ORGANIZATION_ACCESS_DRAFT,
        scope: 'everyUnit',
        everyUnitExclusions: ['sandbox'],
        childUnitsAccess: 'all',
      }),
    ).toEqual([{scope: 'allOus', excludedOuIds: ['sandbox']}]);
  });

  it('round-trips a policy through the draft', () => {
    const policy: SharingPolicy = {
      id: 'p1',
      stage: 'share',
      version: 3,
      targets: [
        {scope: 'allChildren', excludedOuIds: ['trials']},
        {scope: 'allRoots', excludedOuIds: ['contoso']},
      ],
    };

    expect(draftToSharingTargets(sharingPolicyToDraft(policy))).toEqual(policy.targets);
  });
});
