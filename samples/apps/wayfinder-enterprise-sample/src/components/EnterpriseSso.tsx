// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

'use client';

import {
  ConnectionList,
  FlowConnectionBinding,
  OIDCConnectionCreate,
  OIDCConnectionDetails,
} from '@thunderid/nextjs';
import { useState } from 'react';

interface EnterpriseSsoProps {
  callbackUrl: string;
  ouHandle?: string;
  ouId: string;
  signInFlowId: string;
}

type SidePanel = { kind: 'add' } | { kind: 'details'; connectionId: string; isOwned: boolean } | null;

/**
 * ThunderID admin components for the company's enterprise SSO. The identity providers section lists the
 * company's OpenID Connect providers, shows one with its settings, and adds or edits them. The sign-in
 * connection section selects which of them the shared sign-in flow uses for this company.
 */
export default function EnterpriseSso({ callbackUrl, ouHandle, ouId, signInFlowId }: EnterpriseSsoProps) {
  const [panel, setPanel] = useState<SidePanel>(null);

  return (
    <div className="stack">
      <section className="panel steps">
        <h2>How it works</h2>
        <ol>
          <li>
            In your identity provider, register an OpenID Connect application with the callback URL{' '}
            <code>{callbackUrl}</code>.
          </li>
          <li>Add the identity provider here with that application&apos;s client ID and secret.</li>
          <li>Select it as your company&apos;s sign-in connection.</li>
          <li>
            Employees choose <strong>Sign in with enterprise SSO</strong> and enter{' '}
            <code>{ouHandle ?? 'your organization handle'}</code>. First-time employees join your company as members.
          </li>
        </ol>
      </section>

      <div className="two-column">
        <section className="panel">
          <ConnectionList
            ouId={ouId}
            connectionTypes={['oidc']}
            description="Select an identity provider to see and edit its settings."
            selectedConnectionId={panel?.kind === 'details' ? panel.connectionId : undefined}
            onSelect={(connection) =>
              setPanel({ kind: 'details', connectionId: connection.id, isOwned: connection.isOwnedByOU !== false })
            }
            actions={
              <button type="button" className="button primary small" onClick={() => setPanel({ kind: 'add' })}>
                Add identity provider
              </button>
            }
          />
        </section>

        <section className="panel">
          {panel?.kind === 'add' && (
            <OIDCConnectionCreate
              ouId={ouId}
              defaultValues={{ redirectUri: callbackUrl, scopes: 'openid profile email' }}
              onCancel={() => setPanel(null)}
              onCreated={(connection) => setPanel({ kind: 'details', connectionId: connection.id, isOwned: true })}
            />
          )}
          {panel?.kind === 'details' && (
            <OIDCConnectionDetails key={panel.connectionId} connectionId={panel.connectionId} editable={panel.isOwned} />
          )}
          {panel === null && (
            <p className="muted empty-panel">
              Select an identity provider to see its settings, or choose <strong>Add identity provider</strong>.
            </p>
          )}
        </section>
      </div>

      <section className="panel">
        <FlowConnectionBinding
          ouId={ouId}
          flowId={signInFlowId}
          variable="enterpriseIdp"
          connectionTypes={['oidc']}
          title="Enterprise SSO connection"
          description="The identity provider employees sign in with when they choose enterprise SSO."
        />
      </section>
    </div>
  );
}
