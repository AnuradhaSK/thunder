// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package policyengine

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

// EditTestSuite covers which edits a policy admits: the scope families, the blanket narrow-only
// rule, and the version check.
type EditTestSuite struct {
	suite.Suite
}

func TestEditTestSuite(t *testing.T) {
	suite.Run(t, new(EditTestSuite))
}

// withTargets returns a policy carrying the given targets.
func withTargets(targets ...Target) Policy {
	return Policy{ID: "p1", OwningOUID: owner, InitiatingOUID: owner, Stage: StageShare, Targets: targets}
}

// Every target scope belongs to exactly one family, which is what the edit rules key off.
func (s *EditTestSuite) TestFamilyOf() {
	blanket := []TargetScope{TargetScopeAllOUs, TargetScopeAllRoots, TargetScopeAllChildren}
	selective := []TargetScope{TargetScopeRoot, TargetScopeOU, TargetScopeOUSubtree}

	for _, scope := range blanket {
		s.Equal(FamilyBlanket, FamilyOf(scope), string(scope))
	}
	for _, scope := range selective {
		s.Equal(FamilySelective, FamilyOf(scope), string(scope))
	}
}

// A blanket policy already reaches everything in its family, so an edit may only carve out of it.
func (s *EditTestSuite) TestValidateEditBlanketMayOnlyBeNarrowed() {
	current := withTargets(Target{ID: "t1", Scope: TargetScopeAllChildren, OUID: owner})

	s.Run("keeping the same scope is allowed, so exclusions may change around it", func() {
		proposed := withTargets(Target{ID: "t1", Scope: TargetScopeAllChildren, OUID: owner})
		proposed.ExcludedOUIDs = []string{childA}

		s.NoError(ValidateEdit(current, proposed, 1, 1))
	})

	// Converting a blanket policy would change the meaning of every reshare derived from it.
	s.Run("changing the blanket scope itself is rejected", func() {
		proposed := withTargets(Target{ID: "t1", Scope: TargetScopeAllOUs})

		s.ErrorIs(ValidateEdit(current, proposed, 1, 1), ErrBlanketScopeNarrowOnly)
	})

	s.Run("adding a target to a blanket policy is rejected", func() {
		proposed := withTargets(
			Target{ID: "t1", Scope: TargetScopeAllChildren, OUID: owner},
			Target{ID: "t2", Scope: TargetScopeAllChildren, OUID: childA},
		)

		s.ErrorIs(ValidateEdit(current, proposed, 1, 1), ErrBlanketScopeNarrowOnly)
	})
}

// A selective policy may grow within the one-hop rule, which creates no authority its initiator
// did not already hold when the policy was first checked.
func (s *EditTestSuite) TestValidateEditSelectiveMayGrow() {
	current := withTargets(Target{ID: "t1", Scope: TargetScopeOU, OUID: childA})

	// Expansion within the one-hop rule creates no authority the initiator did not already have:
	// it could have named the same children in the original call.
	s.Run("adding a target is allowed", func() {
		proposed := withTargets(
			Target{ID: "t1", Scope: TargetScopeOU, OUID: childA},
			Target{ID: "t2", Scope: TargetScopeOU, OUID: "child-b"},
		)

		s.NoError(ValidateEdit(current, proposed, 1, 1))
	})

	s.Run("flipping a target to carry its subtree is allowed", func() {
		proposed := withTargets(Target{ID: "t1", Scope: TargetScopeOUSubtree, OUID: childA})

		s.NoError(ValidateEdit(current, proposed, 1, 1))
	})

	s.Run("removing a target is allowed", func() {
		start := withTargets(
			Target{ID: "t1", Scope: TargetScopeOU, OUID: childA},
			Target{ID: "t2", Scope: TargetScopeOU, OUID: "child-b"},
		)
		proposed := withTargets(Target{ID: "t1", Scope: TargetScopeOU, OUID: childA})

		s.NoError(ValidateEdit(start, proposed, 1, 1))
	})
}

// Converting between the families would change the meaning of every reshare derived from the
// policy, so it is refused in both directions.
func (s *EditTestSuite) TestValidateEditCannotChangeFamily() {
	selective := withTargets(Target{ID: "t1", Scope: TargetScopeOU, OUID: childA})
	blanket := withTargets(Target{ID: "t1", Scope: TargetScopeAllChildren, OUID: owner})

	s.ErrorIs(ValidateEdit(selective, blanket, 1, 1), ErrScopeFamilyChange)
	s.ErrorIs(ValidateEdit(blanket, selective, 1, 1), ErrScopeFamilyChange)
}

// A declared policy is editable: the file states where sharing starts, and narrowing it afterwards
// is the expected flow. Its scope family still governs what an edit may do.
func (s *EditTestSuite) TestValidateEditAllowsNarrowingADeclaredPolicy() {
	current := withTargets(Target{ID: "t1", Scope: TargetScopeAllOUs})
	current.Declared = true
	proposed := withTargets(Target{ID: "t1", Scope: TargetScopeAllOUs})
	proposed.ExcludedOUIDs = []string{childA}

	s.NoError(ValidateEdit(current, proposed, 1, 1))
}

// Editability does not lift the family rules: a declared blanket policy is still narrow-only.
func (s *EditTestSuite) TestValidateEditHoldsADeclaredBlanketPolicyToItsFamily() {
	current := withTargets(Target{ID: "t1", Scope: TargetScopeAllOUs})
	current.Declared = true
	proposed := withTargets(Target{ID: "t1", Scope: TargetScopeOU, OUID: childA})

	s.ErrorIs(ValidateEdit(current, proposed, 1, 1), ErrScopeFamilyChange)
}

// Exclusions are the only thing that narrows a blanket policy, so an edit may add them but never
// drop one: doing so restores visibility to an organization unit deliberately carved out.
func (s *EditTestSuite) TestValidateEditBlanketExclusionsAreAddOnly() {
	blanket := func(excluded ...string) Policy {
		return Policy{
			Targets:       []Target{{ID: "t1", Scope: TargetScopeAllOUs}},
			ExcludedOUIDs: excluded,
		}
	}

	s.Run("adding one is allowed", func() {
		err := ValidateEdit(blanket("ou-1"), blanket("ou-1", "ou-2"), 1, 1)
		s.NoError(err)
	})

	s.Run("keeping the same set is allowed", func() {
		err := ValidateEdit(blanket("ou-1"), blanket("ou-1"), 1, 1)
		s.NoError(err)
	})

	s.Run("dropping one is refused", func() {
		err := ValidateEdit(blanket("ou-1", "ou-2"), blanket("ou-1"), 1, 1)
		s.ErrorIs(err, ErrBlanketScopeNarrowOnly)
	})

	// A selective policy may grow within the one-hop rule, so it is not held to the same rule.
	s.Run("a selective policy may drop one", func() {
		selective := func(excluded ...string) Policy {
			return Policy{
				Targets:       []Target{{ID: "t1", Scope: TargetScopeOU, OUID: "ou-9"}},
				ExcludedOUIDs: excluded,
			}
		}
		err := ValidateEdit(selective("ou-1", "ou-2"), selective("ou-1"), 1, 1)
		s.NoError(err)
	})
}
