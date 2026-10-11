// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

import {describe, it, expect} from 'vitest';
import type {SharingPolicy, SharingTarget} from '../../models/sharing-policy';
import sharingPolicyToDraft from '../sharingPolicyToDraft';
import switchOrganizationAccess from '../switchOrganizationAccess';

const policyWith = (targets: SharingTarget[]): SharingPolicy => ({id: 'p1', stage: 'share', version: 1, targets});

describe('switchOrganizationAccess', () => {
  it('clears the exceptions when leaving all child units', () => {
    const saved = policyWith([{scope: 'allChildren', excludedOuIds: ['trials']}]);
    const result = switchOrganizationAccess(sharingPolicyToDraft(saved), 'childUnitsAccess', 'selected', saved);

    expect(result.next.childUnitsAccess).toBe('selected');
    expect(result.next.childUnitExclusions).toEqual([]);
    expect(result.cleared).toEqual([{kind: 'childUnitExclusions', ouIds: ['trials']}]);
    expect(result.losesEveryTree).toBe(false);
  });

  it('clears the granted units when leaving selected child units, and keeps the trees', () => {
    const saved = policyWith([
      {scope: 'child', ouId: 'retail'},
      {scope: 'root', ouId: 'northwind'},
    ]);
    const result = switchOrganizationAccess(sharingPolicyToDraft(saved), 'childUnitsAccess', 'none', saved);

    expect(result.next.childUnits).toEqual([]);
    expect(result.next.trees).toEqual(['northwind']);
    expect(result.cleared).toEqual([{kind: 'childUnits', ouIds: ['retail']}]);
  });

  it('clears the trees when leaving selected trees, and keeps the child units', () => {
    const saved = policyWith([{scope: 'allChildren'}, {scope: 'root', ouId: 'northwind'}]);
    const result = switchOrganizationAccess(sharingPolicyToDraft(saved), 'otherTreesAccess', 'none', saved);

    expect(result.next.childUnitsAccess).toBe('all');
    expect(result.cleared).toEqual([{kind: 'trees', ouIds: ['northwind']}]);
  });

  it('clears both sections when stopping sharing', () => {
    const saved = policyWith([
      {scope: 'child', ouId: 'retail'},
      {scope: 'root', ouId: 'northwind'},
    ]);
    const result = switchOrganizationAccess(sharingPolicyToDraft(saved), 'scope', 'owner', saved);

    expect(result.next.scope).toBe('owner');
    expect(result.next.childUnitsAccess).toBe('none');
    expect(result.next.otherTreesAccess).toBe('none');
    expect(result.cleared).toEqual([
      {kind: 'childUnits', ouIds: ['retail']},
      {kind: 'trees', ouIds: ['northwind']},
    ]);
  });

  it('clears nothing when choosing units for an unshared resource', () => {
    const result = switchOrganizationAccess(sharingPolicyToDraft(undefined), 'scope', 'chosen', undefined);

    expect(result.next.scope).toBe('chosen');
    expect(result.cleared).toEqual([]);
  });

  it('reports losing every organization unit, exceptions included', () => {
    const saved = policyWith([{scope: 'allOus', excludedOuIds: ['sandbox']}]);
    const result = switchOrganizationAccess(sharingPolicyToDraft(saved), 'scope', 'chosen', saved);

    expect(result.next.everyUnitExclusions).toEqual([]);
    expect(result.losesEveryUnit).toBe(true);
    expect(result.cleared).toEqual([{kind: 'everyUnit', ouIds: ['sandbox']}]);
  });

  it('drops every tree when leaving all child units changes the blanket targets', () => {
    const saved = policyWith([{scope: 'allChildren'}, {scope: 'allRoots', excludedOuIds: ['contoso']}]);
    const result = switchOrganizationAccess(sharingPolicyToDraft(saved), 'childUnitsAccess', 'selected', saved);

    expect(result.next.otherTreesAccess).toBe('none');
    expect(result.losesEveryTree).toBe(true);
    expect(result.cleared).toContainEqual({kind: 'everyTree', ouIds: ['contoso']});
  });

  it('drops every tree when adding all child units beside it', () => {
    const saved = policyWith([{scope: 'child', ouId: 'retail'}, {scope: 'allRoots'}]);
    const result = switchOrganizationAccess(sharingPolicyToDraft(saved), 'childUnitsAccess', 'all', saved);

    expect(result.losesEveryTree).toBe(true);
  });

  it('keeps every tree when the child units switch between selective choices', () => {
    const saved = policyWith([{scope: 'child', ouId: 'retail'}, {scope: 'allRoots'}]);
    const result = switchOrganizationAccess(sharingPolicyToDraft(saved), 'childUnitsAccess', 'none', saved);

    expect(result.next.otherTreesAccess).toBe('every');
    expect(result.losesEveryTree).toBe(false);
  });

  it('clears the every-tree exceptions when picking trees instead', () => {
    const saved = policyWith([{scope: 'allChildren'}, {scope: 'allRoots', excludedOuIds: ['contoso']}]);
    const result = switchOrganizationAccess(sharingPolicyToDraft(saved), 'otherTreesAccess', 'selected', saved);

    expect(result.next.everyTreeExclusions).toEqual([]);
    expect(result.cleared).toEqual([{kind: 'everyTree', ouIds: ['contoso']}]);
  });
});
