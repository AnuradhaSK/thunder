// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

import type {SharingPolicySavePlan} from '../models/organization-access';
import type {SharingPolicy, SharingScope, SharingTarget} from '../models/sharing-policy';

const BLANKET_SCOPES: SharingScope[] = ['allChildren', 'allOus', 'allRoots'];

function targetKey(target: SharingTarget): string {
  const excluded = [...(target.excludedOuIds ?? [])].sort().join(',');
  return `${target.scope}|${target.ouId ?? ''}|${excluded}`;
}

function blanketScopes(targets: SharingTarget[]): string {
  return targets
    .map((target) => target.scope)
    .filter((scope) => BLANKET_SCOPES.includes(scope))
    .sort()
    .join(',');
}

/**
 * Reports whether two target lists reach the same organization units in the same way, ignoring
 * order.
 */
export function haveSameSharingTargets(a: SharingTarget[], b: SharingTarget[]): boolean {
  const left = a.map(targetKey).sort();
  const right = b.map(targetKey).sort();
  return left.length === right.length && left.every((key, index) => key === right[index]);
}

/**
 * Reports whether a policy holding `current` can become `next` through an edit.
 *
 * The scope a blanket target names is fixed once a policy exists. An edit may rewrite its
 * exclusions and add or drop selective targets beside it, but adding, dropping or swapping a
 * blanket target is a different policy.
 */
export function canEditSharingTargetsInPlace(current: SharingTarget[], next: SharingTarget[]): boolean {
  return blanketScopes(current) === blanketScopes(next);
}

/**
 * Decides what saving a set of targets does to a resource's owner-issued sharing policy.
 *
 * @param current - The policy as last read, or `undefined` when the resource is not shared
 * @param targets - The targets the resource should have after the save
 * @returns The requests the save takes
 */
export default function planSharingPolicySave(
  current: SharingPolicy | undefined,
  targets: SharingTarget[],
): SharingPolicySavePlan {
  if (targets.length === 0) {
    return current ? {type: 'delete', policyId: current.id} : {type: 'none'};
  }
  if (!current) {
    return {type: 'create', targets};
  }
  if (haveSameSharingTargets(current.targets, targets)) {
    return {type: 'none'};
  }
  if (canEditSharingTargetsInPlace(current.targets, targets)) {
    return {type: 'update', policyId: current.id, version: current.version, targets};
  }
  return {type: 'replace', policyId: current.id, targets};
}
