// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

import { redirect } from 'next/navigation';
import AuthButtons from '@/components/AuthButtons';
import { getSessionUser } from '@/lib/auth';

const FEATURES = [
  {
    title: 'Your company, your workspace',
    text: 'Register your company in a minute. You become its admin, and your team’s data stays with your company.',
  },
  {
    title: 'Travel policies that hold',
    text: 'Set the cabin and fare limits once. Employees see what is in policy, and the booking API enforces it.',
  },
  {
    title: 'Sign in your way',
    text: 'Use a Wayfinder password, or connect your own identity provider so employees sign in with enterprise SSO.',
  },
];

export default async function LandingPage() {
  if (await getSessionUser()) {
    redirect('/workspace');
  }

  return (
    <div className="public-shell">
      <header className="public-header">
        <img className="brand-logo" src="/wayfinder-logo.svg" alt="Wayfinder Enterprise" width={232} height={48} />
        <AuthButtons />
      </header>

      <main>
        <section className="hero">
          <p className="eyebrow">Corporate travel, managed</p>
          <h1>Travel management for every company you work with.</h1>
          <p className="hero-lead">
            Wayfinder Enterprise gives each company its own workspace: admins set travel policies and manage their
            team, and employees book flights within policy. Sign-in, roles and enterprise SSO come from ThunderID.
          </p>
        </section>

        <section className="feature-grid" aria-label="Features">
          {FEATURES.map((feature) => (
            <article key={feature.title} className="feature-card">
              <h2>{feature.title}</h2>
              <p>{feature.text}</p>
            </article>
          ))}
        </section>
      </main>

      <footer className="public-footer">A ThunderID sample application.</footer>
    </div>
  );
}
