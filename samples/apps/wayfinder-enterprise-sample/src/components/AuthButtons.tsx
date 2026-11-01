// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

'use client';

import { SignInButton } from '@thunderid/nextjs';

/**
 * Both buttons start sign-in at ThunderID. Its sign-in page offers a password, enterprise SSO, or
 * registering a company. Registering runs the app's sign-up flow inside the sign-in, so the new admin
 * comes back to the app already signed in.
 */
export default function AuthButtons() {
  return (
    <div className="auth-buttons">
      <SignInButton>
        {({ isLoading, signIn }) => (
          <>
            <button type="button" className="button secondary" disabled={isLoading} onClick={() => void signIn()}>
              Sign in
            </button>
            <button type="button" className="button primary" disabled={isLoading} onClick={() => void signIn()}>
              Register your company
            </button>
          </>
        )}
      </SignInButton>
    </div>
  );
}
