// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package policyengine

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

// LineageTestSuite covers the dependency ordering an export replays in, where a parent has to
// precede everything it covers.
type LineageTestSuite struct {
	suite.Suite
}

func TestLineageTestSuite(t *testing.T) {
	suite.Run(t, new(LineageTestSuite))
}

// indexOf returns the position of id in the ordered lineages.
func (s *LineageTestSuite) indexOf(ordered []Lineage, id string) int {
	s.T().Helper()
	for i, l := range ordered {
		if l.ID == id {
			return i
		}
	}
	s.Require().Failf("missing lineage", "id %s not in result", id)
	return -1
}

// Replaying an export in this order keeps every step valid, because the policy that makes an
// initiator visible is applied before the policy that initiator issued.
func (s *LineageTestSuite) TestOrderByDependencyPutsParentsFirst() {
	// Deliberately supplied children-first, so a stable sort alone would not produce the answer.
	ordered := OrderByDependency([]Lineage{
		{ID: "grandchild", ParentID: "child"},
		{ID: "child", ParentID: "root"},
		{ID: "root"},
	})

	s.Require().Len(ordered, 3)
	s.Less(s.indexOf(ordered, "root"), s.indexOf(ordered, "child"))
	s.Less(s.indexOf(ordered, "child"), s.indexOf(ordered, "grandchild"))
}

// An export of one resource has to replay on its own, so a parent outside the set is a root here
// rather than an unsatisfiable dependency.
func (s *LineageTestSuite) TestOrderByDependencyTreatsAnAbsentParentAsARoot() {
	ordered := OrderByDependency([]Lineage{
		{ID: "derived", ParentID: "not-in-this-export"},
	})

	s.Require().Len(ordered, 1)
	s.Equal("derived", ordered[0].ID)
}

// A cycle cannot arise from a well-formed graph, but the remainder is still emitted rather than
// silently dropped.
func (s *LineageTestSuite) TestOrderByDependencyKeepsEveryPolicyOnACycle() {
	ordered := OrderByDependency([]Lineage{
		{ID: "a", ParentID: "b"},
		{ID: "b", ParentID: "a"},
	})

	s.Len(ordered, 2, "a malformed graph must not silently lose policies")
}

// Two entries sharing an id must both be emitted. Tracking placement by id instead of by position
// leaves the second one permanently unplaceable, and the loop never finishes; the test binary's own
// timeout is what surfaces that.
func (s *LineageTestSuite) TestOrderByDependencyKeepsBothEntriesWhenIDsCollide() {
	ordered := OrderByDependency([]Lineage{{ID: "a"}, {ID: "a"}})

	s.Len(ordered, 2, "a duplicate id must not be dropped")
}

// A duplicate id must not disturb the ordering of the entries around it.
func (s *LineageTestSuite) TestOrderByDependencyStillOrdersAroundACollidingID() {
	ordered := OrderByDependency([]Lineage{
		{ID: "child", ParentID: "dup"},
		{ID: "dup"},
		{ID: "dup"},
	})

	s.Require().Len(ordered, 3)
	s.Less(s.indexOf(ordered, "dup"), s.indexOf(ordered, "child"),
		"the parent still precedes what derives from it")
}
