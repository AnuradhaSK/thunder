// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * The breadth one sharing target reaches. `allOus` and `allRoots` only come from a resource file or
 * an imported document: a create may not name them, and an edit may only keep them.
 */
export type SharingScope = 'allChildren' | 'child' | 'childSubtree' | 'root' | 'allOus' | 'allRoots';

/**
 * One organization unit selection of a sharing policy.
 */
export interface SharingTarget {
  scope: SharingScope;
  /**
   * The organization unit the scope anchors on. Absent for `allChildren`, `allOus` and `allRoots`.
   */
  ouId?: string;
  /**
   * Organization units carved out of this target, each taking its subtree with it.
   */
  excludedOuIds?: string[];
}

/**
 * A recorded sharing policy, as every resource that mounts sharing endpoints returns it.
 */
export interface SharingPolicy {
  id: string;
  /**
   * The organization unit whose decision this policy is. Absent means the resource's owner.
   */
  initiatingOuId?: string;
  /**
   * `share` when the owner issued it, `reshare` when a unit it reached passed access on.
   */
  stage: 'share' | 'reshare';
  parentPolicyId?: string;
  /**
   * Set when a resource file declares the policy. It cannot be edited or deleted through the API.
   */
  isReadOnly?: boolean;
  version: number;
  targets: SharingTarget[];
}

export interface SharingPolicyListResponse {
  totalResults: number;
  startIndex: number;
  count: number;
  policies: SharingPolicy[];
}

/**
 * The body of a sharing policy create or replace.
 */
export interface SharingPolicyRequest {
  targets: SharingTarget[];
  /**
   * The version the caller believes it is editing. Required on a replace, ignored on a create.
   */
  version?: number;
}
