// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package policyengine

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

// ContainmentTestSuite covers member comparison for the three field kinds, including the prefix
// containment a hierarchy field needs its own delimiter for.
type ContainmentTestSuite struct {
	suite.Suite
}

func TestContainmentTestSuite(t *testing.T) {
	suite.Run(t, new(ContainmentTestSuite))
}

// Containment means equality for a reference set and path descent for a hierarchy, so the same
// pair of members is covered under one kind and not the other.
func (s *ContainmentTestSuite) TestCoversByKind() {
	tests := []struct {
		name  string
		kind  FieldKind
		outer string
		inner string
		want  bool
	}{
		{"scalar equal", FieldScalar, "totp", "totp", true},
		{"scalar different", FieldScalar, "totp", "sms-otp", false},
		{"reference equal", FieldReferenceSet, "group-1", "group-1", true},
		{"reference different", FieldReferenceSet, "group-1", "group-2", false},
		// A reference id that happens to share a prefix must not be treated as hierarchical.
		{"reference prefix is not containment", FieldReferenceSet, "group", "group:1", false},
		{"hierarchy self", FieldHierarchy, "bookings", "bookings", true},
		{"hierarchy descendant", FieldHierarchy, "bookings", "bookings:create", true},
		{"hierarchy deep descendant", FieldHierarchy, "billing", "billing:invoice:view", true},
		{"hierarchy ancestor does not cover upward", FieldHierarchy, "bookings:create", "bookings", false},
		{"hierarchy sibling", FieldHierarchy, "bookings", "billing", false},
		// "bookings" must not cover "bookingsx": containment is by segment, not by string prefix.
		{"hierarchy partial segment is not containment", FieldHierarchy, "bookings", "bookingsx", false},
	}
	for _, tt := range tests {
		s.Run(tt.name, func() {
			c := NewContainment(tt.kind, ":")
			s.Equal(tt.want, c.Covers(tt.outer, tt.inner))
		})
	}
}

// A set is covered only when every one of its members is covered by some member of the outer set.
func (s *ContainmentTestSuite) TestSetCovers() {
	c := NewContainment(FieldHierarchy, ":")

	s.True(c.SetCovers([]string{"bookings", "billing"}, []string{"bookings:create", "billing"}))
	s.False(c.SetCovers([]string{"bookings"}, []string{"bookings:create", "billing"}))
	// An empty inner set is covered by anything, including an empty outer set.
	s.True(c.SetCovers(nil, nil))
	s.False(c.SetCovers(nil, []string{"bookings"}))
}

// Subtracting a hierarchy member takes everything beneath it, not just the exact path.
func (s *ContainmentTestSuite) TestSubtractRemovesSubtrees() {
	c := NewContainment(FieldHierarchy, ":")

	got := c.Subtract(
		[]string{"bookings", "bookings:create", "billing:invoice"},
		[]string{"bookings"},
	)

	s.Equal([]string{"billing:invoice"}, got)
}

// Intersecting a path with one beneath it yields the deeper path, which is the narrower grant.
func (s *ContainmentTestSuite) TestIntersectMembersKeepsTheNarrowerPath() {
	c := NewContainment(FieldHierarchy, ":")

	got := c.IntersectMembers([]string{"billing"}, []string{"billing:invoice"})

	s.Equal([]string{"billing:invoice"}, got)
}

// Only members present on both sides survive an intersection.
func (s *ContainmentTestSuite) TestIntersectMembersDropsDisjointEntries() {
	c := NewContainment(FieldReferenceSet, "")

	got := c.IntersectMembers([]string{"a", "b"}, []string{"b", "c"})

	s.Equal([]string{"b"}, got)
}

// A path already covered by an ancestor in the same union adds nothing, so it is folded away.
func (s *ContainmentTestSuite) TestUnionDropsRedundantDescendants() {
	c := NewContainment(FieldHierarchy, ":")

	got := c.Union([]string{"billing", "billing:invoice"}, []string{"bookings"})

	s.ElementsMatch([]string{"billing", "bookings"}, got)
}

// A union is a set: the same member twice collapses to one entry.
func (s *ContainmentTestSuite) TestUnionKeepsOneOfTwoIdenticalMembers() {
	c := NewContainment(FieldReferenceSet, "")

	got := c.Union([]string{"a"}, []string{"a"})

	s.Equal([]string{"a"}, got)
}
