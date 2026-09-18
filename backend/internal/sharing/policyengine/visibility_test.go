// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package policyengine

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

// VisibilityTestSuite covers the chain walk that decides whether an organization unit can see a
// resource, and which policy covered it.
type VisibilityTestSuite struct {
	suite.Suite
}

func TestVisibilityTestSuite(t *testing.T) {
	suite.Run(t, new(VisibilityTestSuite))
}

const (
	owner  = "owner-ou"
	rootA  = "root-a"
	childA = "child-a"
	grandA = "grand-a"
)

// policy builds a share-stage policy owned by owner with one target.
func policy(id string, scope TargetScope, targetOU string, excluded ...string) Policy {
	return Policy{
		ID: id, OwningOUID: owner, InitiatingOUID: owner, Stage: StageShare,
		Targets:       []Target{{ID: id + "-t", Scope: scope, OUID: targetOU}},
		ExcludedOUIDs: excluded,
	}
}

// reshare builds a reshare-stage policy issued by initiator with one target.
func reshare(id, initiator string, scope TargetScope, targetOU string, excluded ...string) Policy {
	p := policy(id, scope, targetOU, excluded...)
	p.Stage = StageReshare
	p.InitiatingOUID = initiator
	return p
}

// The owner holds its own resource, so it is visible whatever the policies say.
func (s *VisibilityTestSuite) TestEvaluateChainOwnerIsAlwaysVisible() {
	visible, covering := EvaluateChain([]string{owner}, []Policy{policy("p1", TargetScopeRoot, rootA)})

	s.True(visible)
	// The owner needs no policy of its own, so nothing is recorded as covering it.
	s.Empty(covering)
}

// The three root-facing scopes each decide whether a tree's root is reached.
func (s *VisibilityTestSuite) TestEvaluateChainRootTargeting() {
	tests := []struct {
		name     string
		policies []Policy
		want     bool
	}{
		{"named root", []Policy{policy("p1", TargetScopeRoot, rootA)}, true},
		{"a different root", []Policy{policy("p1", TargetScopeRoot, "root-b")}, false},
		{"all roots", []Policy{policy("p1", TargetScopeAllRoots, "")}, true},
		{"all roots minus this one", []Policy{policy("p1", TargetScopeAllRoots, "", rootA)}, false},
		// Root targeting is owner-only, so a reshare must never reach a root.
		{"a reshare cannot reach a root", []Policy{reshare("p1", childA, TargetScopeRoot, rootA)}, false},
	}
	for _, tt := range tests {
		s.Run(tt.name, func() {
			visible, _ := EvaluateChain([]string{rootA}, tt.policies)
			s.Equal(tt.want, visible)
		})
	}
}

// Visibility is carried hop by hop: reaching a root does not by itself reach anything below it.
func (s *VisibilityTestSuite) TestEvaluateChainRequiresEveryHop() {
	// The root is reached, but nothing carries the resource further down.
	visible, _ := EvaluateChain(
		[]string{rootA, childA},
		[]Policy{policy("p1", TargetScopeRoot, rootA)},
	)
	s.False(visible, "a child is not visible merely because its root is")
}

// An all-children scope reaches every depth beneath its anchor, not only the first level.
func (s *VisibilityTestSuite) TestEvaluateChainSubtreeReachesAnyDepth() {
	policies := []Policy{
		policy("p1", TargetScopeRoot, rootA),
		reshare("p2", rootA, TargetScopeAllChildren, rootA),
	}

	visible, covering := EvaluateChain([]string{rootA, childA, grandA}, policies)

	s.True(visible)
	s.Require().Len(covering, 1)
	s.Equal("p2", covering[0].Policy.ID)
}

// An excluded organization unit takes its whole subtree with it.
func (s *VisibilityTestSuite) TestEvaluateChainExclusionCutsOffEverythingBelow() {
	policies := []Policy{
		policy("p1", TargetScopeRoot, rootA),
		reshare("p2", rootA, TargetScopeAllChildren, rootA, childA),
	}

	childVisible, _ := EvaluateChain([]string{rootA, childA}, policies)
	grandVisible, _ := EvaluateChain([]string{rootA, childA, grandA}, policies)

	s.False(childVisible)
	s.False(grandVisible, "an excluded organization unit takes its subtree with it")
}

// Naming a grandchild directly does not reach it: depth comes from a subtree scope, never from
// naming deeper.
func (s *VisibilityTestSuite) TestEvaluateChainExplicitTargetNeverSkipsAHop() {
	// The root names a grandchild directly, which must not reach it.
	policies := []Policy{
		policy("p1", TargetScopeRoot, rootA),
		reshare("p2", rootA, TargetScopeOU, grandA),
	}

	visible, _ := EvaluateChain([]string{rootA, childA, grandA}, policies)

	s.False(visible)
}

// A subtree target reaches the organization unit it names as well as everything beneath it.
func (s *VisibilityTestSuite) TestEvaluateChainSubtreeTargetCoversItsAnchorAndBelow() {
	policies := []Policy{
		policy("p1", TargetScopeRoot, rootA),
		reshare("p2", rootA, TargetScopeOUSubtree, childA),
	}

	anchorVisible, _ := EvaluateChain([]string{rootA, childA}, policies)
	belowVisible, _ := EvaluateChain([]string{rootA, childA, grandA}, policies)

	s.True(anchorVisible)
	s.True(belowVisible)
}

// The walk itself puts no limit on how many policies can cover a position, which is what peer
// targets will need. The service refuses to create this shape today, by allowing only a unit a
// policy named and stopped at to issue one of its own, so the engine is fed it directly here.
func (s *VisibilityTestSuite) TestEvaluateChainReturnsEveryCoveringPolicy() {
	// A diamond: a subtree reshare and a narrower one below it both reach the same organization
	// unit, and rule resolution needs both to intersect them.
	policies := []Policy{
		policy("p1", TargetScopeRoot, rootA),
		reshare("p2", rootA, TargetScopeAllChildren, rootA),
		reshare("p3", childA, TargetScopeOU, grandA),
	}

	visible, covering := EvaluateChain([]string{rootA, childA, grandA}, policies)

	s.True(visible)
	ids := make([]string, 0, len(covering))
	for _, c := range covering {
		ids = append(ids, c.Policy.ID)
	}
	s.ElementsMatch([]string{"p2", "p3"}, ids)
}

// A blanket policy stands behind the specific ones rather than replacing them.
func (s *VisibilityTestSuite) TestEvaluateChainAllOUsIsAFallbackNotAShadow() {
	allOUs := policy("p-blanket", TargetScopeAllOUs, "")
	specific := reshare("p-specific", rootA, TargetScopeAllChildren, rootA)

	s.Run("it covers where nothing specific reached", func() {
		visible, covering := EvaluateChain([]string{"other-root"}, []Policy{allOUs})
		s.True(visible)
		s.Require().Len(covering, 1)
		s.True(covering[0].ByAllOUs)
	})

	// The point of the carve-out: a deployment-wide policy must not join the intersection and
	// clamp a policy the owner deliberately made narrower.
	s.Run("it stands aside where a specific target reached", func() {
		_, covering := EvaluateChain(
			[]string{rootA, childA},
			[]Policy{policy("p1", TargetScopeRoot, rootA), specific, allOUs},
		)
		s.Require().Len(covering, 1)
		s.Equal("p-specific", covering[0].Policy.ID)
		s.False(covering[0].ByAllOUs)
	})

	s.Run("an exclusion still applies to it", func() {
		visible, _ := EvaluateChain([]string{"other-root"},
			[]Policy{policy("p-blanket", TargetScopeAllOUs, "", "other-root")})
		s.False(visible)
	})
}

// An empty chain names no organization unit, so nothing is visible and nothing covers it.
func (s *VisibilityTestSuite) TestEvaluateChainEmptyInputs() {
	visible, covering := EvaluateChain(nil, []Policy{policy("p1", TargetScopeAllOUs, "")})
	s.False(visible)
	s.Nil(covering)

	visible, covering = EvaluateChain([]string{rootA}, nil)
	s.False(visible)
	s.Nil(covering)
}
