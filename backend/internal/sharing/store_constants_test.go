// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package sharing

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

// StoreConstantsTestSuite covers the chain-scoped query builder, whose WHERE clause has to stay
// parameterized however many organization units the chain holds.
type StoreConstantsTestSuite struct {
	suite.Suite
}

func TestStoreConstantsTestSuite(t *testing.T) {
	suite.Run(t, new(StoreConstantsTestSuite))
}

// An empty chain names no organization unit. Emitting the membership test anyway produces IN (),
// which PostgreSQL rejects outright, so the whole lookup fails rather than returning the blanket
// policies that still apply.
func (s *StoreConstantsTestSuite) TestBuildRelevantPoliciesQueryHandlesAnEmptyChain() {
	query, args := buildRelevantPoliciesQuery(testType, "", nil, "dep-1")

	for name, sql := range map[string]string{
		"postgres": query.PostgresQuery,
		"sqlite":   query.SQLiteQuery,
	} {
		s.Run(name, func() {
			s.NotContains(sql, "IN ()", "an empty list is not valid SQL")
			s.Contains(sql, "all_ous", "blanket policies still have to match")
		})
	}
	s.Equal([]interface{}{"dep-1", string(testType)}, args)
}

// Every chain member needs its own placeholder and argument, in matching order.
func (s *StoreConstantsTestSuite) TestBuildRelevantPoliciesQueryBindsEveryChainMember() {
	query, args := buildRelevantPoliciesQuery(testType, "", []string{"ou-1", "ou-2"}, "dep-1")

	s.Contains(query.PostgresQuery, "TARGET_OU_ID IN ($3,$4)")
	s.Contains(query.SQLiteQuery, "TARGET_OU_ID IN (?,?)")
	s.Require().Len(args, 4)
	s.Equal([]interface{}{"dep-1", string(testType), "ou-1", "ou-2"}, args)
}

// The foreign key on RESOURCE_SHARING_POLICY_TARGET.POLICY_ID checks only the policy id, so a
// target row carrying another deployment's id still satisfies it. Without this join condition such
// a row's target scope would decide visibility across the deployment boundary.
func (s *StoreConstantsTestSuite) TestBuildRelevantPoliciesQueryScopesTheTargetJoinByDeployment() {
	query, _ := buildRelevantPoliciesQuery(testType, "", []string{"ou-1"}, "dep-1")

	for name, sql := range map[string]string{
		"postgres": query.PostgresQuery,
		"sqlite":   query.SQLiteQuery,
	} {
		s.Run(name, func() {
			s.Contains(sql, "t.DEPLOYMENT_ID = p.DEPLOYMENT_ID")
		})
	}
}

// Narrowing to one resource inserts an argument ahead of the chain, so the chain's own placeholders
// shift with it. Binding them by a fixed offset is what would put every chain member in the wrong
// slot, which the database would accept as a perfectly valid query against the wrong ids.
func (s *StoreConstantsTestSuite) TestBuildRelevantPoliciesQueryNarrowsToOneResource() {
	query, args := buildRelevantPoliciesQuery(testType, "res-1", []string{"ou-1", "ou-2"}, "dep-1")

	s.Contains(query.PostgresQuery, "p.RESOURCE_ID = $3")
	s.Contains(query.PostgresQuery, "TARGET_OU_ID IN ($4,$5)")
	s.Contains(query.SQLiteQuery, "p.RESOURCE_ID = ?")
	s.Equal([]interface{}{"dep-1", string(testType), "res-1", "ou-1", "ou-2"}, args)
}

// The reverse lookup asks across every resource of the type, so naming none must not emit a
// predicate that matches nothing.
func (s *StoreConstantsTestSuite) TestBuildRelevantPoliciesQueryWithoutAResourceSpansThemAll() {
	query, args := buildRelevantPoliciesQuery(testType, "", []string{"ou-1"}, "dep-1")

	s.NotContains(query.PostgresQuery, "p.RESOURCE_ID = ",
		"the column is selected, but must not be filtered on")
	s.Contains(query.PostgresQuery, "TARGET_OU_ID IN ($3)")
	s.Equal([]interface{}{"dep-1", string(testType), "ou-1"}, args)
}

// The placeholder styles must not leak into one another's dialect.
func (s *StoreConstantsTestSuite) TestBuildRelevantPoliciesQueryKeepsDialectsApart() {
	query, _ := buildRelevantPoliciesQuery(testType, "", []string{"ou-1"}, "dep-1")

	s.NotContains(query.SQLiteQuery, "$1")
	s.False(strings.Contains(query.PostgresQuery, "IN (?)"))
}
