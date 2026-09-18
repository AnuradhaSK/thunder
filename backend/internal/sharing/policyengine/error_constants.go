// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package policyengine

import "errors"

// Errors returned by the narrowing algebra. The service maps each to its own SHR code.
var (
	// ErrWidens is returned when a rule asks for more than the initiating OU itself holds.
	ErrWidens = errors.New("rule widens what the initiating organization unit holds")
	// ErrValueOutsideAllowed is returned when a rule's value is not within its own allowed set.
	ErrValueOutsideAllowed = errors.New("value is not within allowedValues")
	// ErrPinnedWithAllowed is returned when a non-editable rule also bounds a choice nobody can make.
	ErrPinnedWithAllowed = errors.New("editable false cannot be combined with allowedValues")
)

// Errors returned by edit validation.
var (
	// ErrBlanketScopeNarrowOnly is returned when an edit tries to do more to a blanket policy than
	// add exclusions.
	ErrBlanketScopeNarrowOnly = errors.New("a blanket policy may only be narrowed by exclusions")
	// ErrScopeFamilyChange is returned when an edit tries to convert between scope families.
	ErrScopeFamilyChange = errors.New("a policy cannot change scope family")
	// ErrDeclaredImmutable is returned when an edit targets a declaratively defined policy.
	ErrDeclaredImmutable = errors.New("a declared policy can only be changed in its own file")
	// ErrVersionMismatch is returned when an edit is based on a stale version of the policy.
	ErrVersionMismatch = errors.New("policy version mismatch")
)
