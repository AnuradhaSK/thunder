// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package policyengine

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

// OverlayTestSuite covers the narrowing algebra: what a rule may ask for, how two rules fold, and
// the absent-versus-empty distinction the pointer fields carry.
type OverlayTestSuite struct {
	suite.Suite
}

func TestOverlayTestSuite(t *testing.T) {
	suite.Run(t, new(OverlayTestSuite))
}

// set returns a pointer to a list, for the fields where absent and empty differ.
func set(v ...string) *[]string {
	out := append([]string{}, v...)
	return &out
}

// unconstrained is the open rule an owner starts from for an editable field.
var unconstrained = Rule{Editable: true}

// Validate checks a rule against itself, independent of any parent.
func (s *OverlayTestSuite) TestValidateRule() {
	c := NewContainment(FieldReferenceSet, "")

	tests := []struct {
		name string
		rule Rule
		want error
	}{
		{"open rule", Rule{Editable: true}, nil},
		{"pinned rule", Rule{Editable: false, Value: set("a")}, nil},
		{"menu", Rule{Editable: true, AllowedValues: set("a", "b")}, nil},
		{"seeded and bounded", Rule{Editable: true, Value: set("a"), AllowedValues: set("a", "b")}, nil},
		{
			"a menu nobody may choose from is an authoring mistake",
			Rule{Editable: false, AllowedValues: set("a")},
			ErrPinnedWithAllowed,
		},
		{
			"value outside its own allowed set",
			Rule{Editable: true, Value: set("c"), AllowedValues: set("a", "b")},
			ErrValueOutsideAllowed,
		},
	}
	for _, tt := range tests {
		s.Run(tt.name, func() {
			s.Equal(tt.want, c.Validate(tt.rule))
		})
	}
}

// Editability only ever narrows: an initiator holding editable false cannot hand on true.
func (s *OverlayTestSuite) TestNarrowEditable() {
	c := NewContainment(FieldReferenceSet, "")

	s.Run("false narrows true", func() {
		got, err := c.Narrow(Rule{Editable: true}, Rule{Editable: false})
		s.Require().NoError(err)
		s.False(got.Editable)
	})

	s.Run("true cannot be handed on by an initiator holding false", func() {
		_, err := c.Narrow(Rule{Editable: false}, Rule{Editable: true})
		s.ErrorIs(err, ErrWidens)
	})
}

// A child's bound must sit within its parent's, and an omitted bound inherits rather than
// meaning unconstrained.
func (s *OverlayTestSuite) TestNarrowAllowedValues() {
	c := NewContainment(FieldReferenceSet, "")

	s.Run("a subset is accepted", func() {
		got, err := c.Narrow(
			Rule{Editable: true, AllowedValues: set("a", "b", "c")},
			Rule{Editable: true, AllowedValues: set("a", "b")},
		)
		s.Require().NoError(err)
		s.Equal([]string{"a", "b"}, *got.AllowedValues)
	})

	s.Run("a superset widens", func() {
		_, err := c.Narrow(
			Rule{Editable: true, AllowedValues: set("a")},
			Rule{Editable: true, AllowedValues: set("a", "b")},
		)
		s.ErrorIs(err, ErrWidens)
	})

	// This is the case that makes the pointer types necessary: omitted on the child must inherit
	// the parent's bound, not silently reopen the field.
	s.Run("omitted on the child inherits the parent bound", func() {
		got, err := c.Narrow(Rule{Editable: true, AllowedValues: set("a")}, unconstrained)
		s.Require().NoError(err)
		s.Require().NotNil(got.AllowedValues)
		s.Equal([]string{"a"}, *got.AllowedValues)
	})

	// The opposite of the above: explicitly empty permits nothing and must survive the fold.
	s.Run("explicitly empty on the child permits nothing", func() {
		got, err := c.Narrow(Rule{Editable: true, AllowedValues: set("a")}, Rule{Editable: true, AllowedValues: set()})
		s.Require().NoError(err)
		s.Require().NotNil(got.AllowedValues)
		s.Empty(*got.AllowedValues)
	})

	s.Run("an unconstrained parent accepts any child bound", func() {
		got, err := c.Narrow(unconstrained, Rule{Editable: true, AllowedValues: set("a")})
		s.Require().NoError(err)
		s.Equal([]string{"a"}, *got.AllowedValues)
	})
}

// Value narrowing is decided by the field's containment kind, so a hierarchy compares by path
// descent rather than by equality.
func (s *OverlayTestSuite) TestNarrowValueUsesKindContainment() {
	c := NewContainment(FieldHierarchy, ":")

	s.Run("a descendant path is within an ancestor path", func() {
		got, err := c.Narrow(
			Rule{Editable: false, Value: set("billing")},
			Rule{Editable: false, Value: set("billing:invoice")},
		)
		s.Require().NoError(err)
		s.Equal([]string{"billing:invoice"}, *got.Value)
	})

	s.Run("a sibling path widens", func() {
		_, err := c.Narrow(
			Rule{Editable: false, Value: set("billing")},
			Rule{Editable: false, Value: set("bookings")},
		)
		s.ErrorIs(err, ErrWidens)
	})
}

// Exclusions run opposite to the other fields: more carve-outs are always allowed, un-carving
// never is.
func (s *OverlayTestSuite) TestNarrowExclusionsAreMonotoneTheOtherWay() {
	c := NewContainment(FieldHierarchy, ":")

	s.Run("more carve-outs are allowed", func() {
		got, err := c.Narrow(
			Rule{Editable: false, ExcludedValues: set("billing")},
			Rule{Editable: false, ExcludedValues: set("billing", "bookings")},
		)
		s.Require().NoError(err)
		s.ElementsMatch([]string{"billing", "bookings"}, *got.ExcludedValues)
	})

	s.Run("un-carving is not", func() {
		_, err := c.Narrow(
			Rule{Editable: false, ExcludedValues: set("billing", "bookings")},
			Rule{Editable: false, ExcludedValues: set("billing")},
		)
		s.ErrorIs(err, ErrWidens)
	})
}

// Intersection rather than deepest-wins is what keeps rule resolution monotone: adding a covering
// policy can never widen the result.
func (s *OverlayTestSuite) TestIntersectIsMonotone() {
	c := NewContainment(FieldReferenceSet, "")

	s.Run("editable only survives when every covering rule allows it", func() {
		got := c.Intersect([]Rule{{Editable: true}, {Editable: false}})
		s.False(got.Editable)
	})

	s.Run("allowed sets intersect", func() {
		got := c.Intersect([]Rule{
			{Editable: true, AllowedValues: set("a", "b")},
			{Editable: true, AllowedValues: set("b", "c")},
		})
		s.Equal([]string{"b"}, *got.AllowedValues)
	})

	// An unconstrained rule must not widen the one it is folded with.
	s.Run("an unconstrained rule contributes no bound", func() {
		got := c.Intersect([]Rule{{Editable: true}, {Editable: true, AllowedValues: set("a")}})
		s.Require().NotNil(got.AllowedValues)
		s.Equal([]string{"a"}, *got.AllowedValues)
	})

	// The value and the bound are folded independently, so one rule's value can meet another's
	// bound and carry members that bound never allowed. The fold has to stay closed over rules
	// Validate accepts.
	s.Run("an editable value is clamped to the bound it is folded with", func() {
		got := c.Intersect([]Rule{
			{Editable: true, Value: set("a", "b")},
			{Editable: true, AllowedValues: set("b", "c")},
		})

		s.Require().NotNil(got.Value)
		s.Equal([]string{"b"}, *got.Value, "the value keeps only what the bound allows")
		s.Require().NotNil(got.AllowedValues)
		s.Equal([]string{"b", "c"}, *got.AllowedValues)
		s.NoError(c.Validate(got), "the fold must not produce a rule it would itself reject")
	})

	// Nothing survives when the two are disjoint, which is the honest answer rather than a value
	// standing outside its own menu.
	s.Run("a disjoint bound empties the value", func() {
		got := c.Intersect([]Rule{
			{Editable: true, Value: set("a")},
			{Editable: true, AllowedValues: set("b")},
		})

		s.Require().NotNil(got.Value)
		s.Empty(*got.Value)
		s.NoError(c.Validate(got))
	})

	s.Run("exclusions accumulate", func() {
		got := c.Intersect([]Rule{
			{Editable: true, ExcludedValues: set("a")},
			{Editable: true, ExcludedValues: set("b")},
		})
		s.ElementsMatch([]string{"a", "b"}, *got.ExcludedValues)
	})

	// Effective reads a pinned rule carrying no value of its own as the owner's value, which a
	// surviving bound would never constrain. The fold has to move the bound onto the value, or a
	// policy that allowed only "a" and "b" ends up handing over the owner's "c" as well.
	s.Run("folding a bounded rule with a pinned one keeps the bound", func() {
		got := c.Intersect([]Rule{
			{Editable: true, AllowedValues: set("a", "b")},
			{Editable: false},
		})

		s.Require().NoError(c.Validate(got), "the folded rule must satisfy its own invariant")
		s.Nil(got.AllowedValues, "a pinned rule carries no menu")
		s.Require().NotNil(got.Value)
		s.ElementsMatch([]string{"a", "b"}, *got.Value)

		universe := []string{"a", "b", "c"}
		_, value := c.Effective(got, universe, universe)
		s.NotContains(value, "c", "the owner's value must stay within the bound")
		s.ElementsMatch([]string{"a", "b"}, value)
	})

	// The pinned rule names a value of its own that reaches past the bound. Every rule folded here
	// already applies, so the excess is clamped away rather than refused as Narrow would.
	s.Run("a pinned value reaching past the bound is clamped to it", func() {
		got := c.Intersect([]Rule{
			{Editable: true, AllowedValues: set("a", "b")},
			{Editable: false, Value: set("b", "c")},
		})

		s.Require().NoError(c.Validate(got))
		s.Require().NotNil(got.Value)
		s.ElementsMatch([]string{"b"}, *got.Value)
	})

	// The property the whole choice of intersection over deepest-wins exists to guarantee.
	s.Run("adding a covering rule never widens the result", func() {
		narrow := Rule{Editable: false, AllowedValues: nil, ExcludedValues: set("a")}
		broad := Rule{Editable: true}

		withBoth := c.Intersect([]Rule{broad, narrow})

		s.False(withBoth.Editable, "the broader rule must not restore editability")
		s.ElementsMatch([]string{"a"}, *withBoth.ExcludedValues)
	})
}

// Effective resolves a rule into the concrete allowed set and value a target organization unit
// sees, including the owner-value fallback for a pinned rule.
func (s *OverlayTestSuite) TestEffective() {
	c := NewContainment(FieldHierarchy, ":")
	universe := []string{"bookings", "billing", "reports"}
	ownerValue := []string{"bookings", "billing"}

	s.Run("not editable with no value resolves to the owner's own value", func() {
		allowed, value := c.Effective(Rule{Editable: false}, universe, ownerValue)
		s.Equal(universe, allowed)
		s.Equal(ownerValue, value)
	})

	// "Everything except refunds" needs no wildcard: the owner's value already is everything.
	s.Run("not editable with exclusions is the owner's value minus them", func() {
		_, value := c.Effective(
			Rule{Editable: false, ExcludedValues: set("billing")}, universe, ownerValue)
		s.Equal([]string{"bookings"}, value)
	})

	s.Run("an editable field with no value starts unset", func() {
		_, value := c.Effective(unconstrained, universe, ownerValue)
		s.Empty(value)
	})

	s.Run("a pinned value wins over the owner's", func() {
		_, value := c.Effective(
			Rule{Editable: false, Value: set("reports")}, universe, ownerValue)
		s.Equal([]string{"reports"}, value)
	})

	s.Run("exclusions are subtracted from the allowed set too", func() {
		allowed, _ := c.Effective(
			Rule{Editable: true, AllowedValues: set("bookings", "billing"), ExcludedValues: set("billing")},
			universe, ownerValue)
		s.Equal([]string{"bookings"}, allowed)
	})

	// Explicitly empty must resolve to nothing permitted, not to the universe.
	s.Run("an explicitly empty allowed set permits nothing", func() {
		allowed, _ := c.Effective(Rule{Editable: true, AllowedValues: set()}, universe, ownerValue)
		s.Empty(allowed)
	})
}

// Widens compares two already-materialized rules, where an omitted list means unbounded rather
// than inherited. That reading is the whole point of keeping it separate from Narrow.
func (s *OverlayTestSuite) TestWidens() {
	c := NewContainment(FieldReferenceSet, "")
	bounded := Rule{Editable: true, AllowedValues: set("a", "b")}

	s.Run("dropping a bound widens, because nothing named means everything", func() {
		s.True(c.Widens(bounded, Rule{Editable: true}))
	})

	s.Run("growing a bound widens", func() {
		s.True(c.Widens(bounded, Rule{Editable: true, AllowedValues: set("a", "b", "c")}))
	})

	s.Run("shrinking a bound does not", func() {
		s.False(c.Widens(bounded, Rule{Editable: true, AllowedValues: set("a")}))
	})

	s.Run("gaining editability widens", func() {
		s.True(c.Widens(Rule{Editable: false, Value: set("a")}, Rule{Editable: true}))
	})

	// The case that makes reach necessary: a pinned rule carries no menu, so comparing its absent
	// AllowedValues against the bound would read the narrowest possible edit as a widening.
	s.Run("pinning within the bound does not widen", func() {
		s.False(c.Widens(bounded, Rule{Editable: false, Value: set("a")}))
	})

	s.Run("pinning outside the bound does widen", func() {
		s.True(c.Widens(bounded, Rule{Editable: false, Value: set("c")}))
	})

	// A pinned rule with no value of its own resolves to the owner's whole value.
	s.Run("dropping a pinned value widens", func() {
		s.True(c.Widens(Rule{Editable: false, Value: set("a")}, Rule{Editable: false}))
	})

	s.Run("an unbounded rule cannot be widened", func() {
		s.False(c.Widens(Rule{Editable: true}, Rule{Editable: true, AllowedValues: set("a")}))
	})

	s.Run("dropping a carve-out widens", func() {
		s.True(c.Widens(
			Rule{Editable: true, ExcludedValues: set("x")}, Rule{Editable: true}))
	})

	s.Run("adding a carve-out does not", func() {
		s.False(c.Widens(
			Rule{Editable: true, ExcludedValues: set("x")},
			Rule{Editable: true, ExcludedValues: set("x", "y")}))
	})
}

// Pinning is strictly narrower than an editable menu, so a parent that bounds the field must not
// turn a request carrying no allowedValues into one that is rejected for carrying them.
func (s *OverlayTestSuite) TestNarrowAcceptsPinningUnderABoundedParent() {
	c := NewContainment(FieldReferenceSet, "")

	s.Run("with no value of its own it pins to the parent's bound", func() {
		got, err := c.Narrow(
			Rule{Editable: true, AllowedValues: set("a", "b")},
			Rule{Editable: false},
		)
		s.Require().NoError(err)
		s.False(got.Editable)
		s.Nil(got.AllowedValues, "a pinned rule carries no menu")
		s.Require().NotNil(got.Value)
		s.ElementsMatch([]string{"a", "b"}, *got.Value)
	})

	s.Run("a named value within the bound is kept", func() {
		got, err := c.Narrow(
			Rule{Editable: true, AllowedValues: set("a", "b")},
			Rule{Editable: false, Value: set("a")},
		)
		s.Require().NoError(err)
		s.Nil(got.AllowedValues)
		s.Equal([]string{"a"}, *got.Value)
	})

	// The parent bounds the field but names no value, so value narrowing has nothing to check
	// against; the bound has to do it instead.
	s.Run("a named value outside the bound still widens", func() {
		_, err := c.Narrow(
			Rule{Editable: true, AllowedValues: set("a", "b")},
			Rule{Editable: false, Value: set("c")},
		)
		s.ErrorIs(err, ErrWidens)
	})
}
