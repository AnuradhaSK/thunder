// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

import {describe, it, expect} from 'vitest';
import getOrganizationAccessOffers from '../getOrganizationAccessOffers';

describe('getOrganizationAccessOffers', () => {
  it('offers no deployment-wide choice for an unshared resource', () => {
    expect(getOrganizationAccessOffers(undefined)).toEqual({everyUnit: false, everyTree: false});
  });

  it('offers each deployment-wide choice the saved policy holds', () => {
    expect(
      getOrganizationAccessOffers({
        id: 'p1',
        stage: 'share',
        version: 1,
        targets: [{scope: 'allOus'}, {scope: 'allRoots'}],
      }),
    ).toEqual({everyUnit: true, everyTree: true});
  });
});
