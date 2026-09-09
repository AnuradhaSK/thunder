// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package sharing

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	_ "modernc.org/sqlite"
)

// SQLiteVisibilityTestSuite runs buildRelevantGrantsQuery's generated SQL against a real,
// in-memory SQLite database. Every other sharing test mocks QueryContext, which validates that
// the store calls the DB client with the right arguments but never proves the generated SQL text
// itself is valid, or that the dynamic IN (...) placeholder list lines up correctly with SQLite's
// positional '?' binding. This suite exercises the real driver to close that gap. The actual
// coverage-evaluation logic (chain walking, exclusion checks, chain integrity) lives in
// evaluateChainVisibility and is covered by service_test.go's pure-Go tests instead, since it has
// no SQL of its own to validate.
type SQLiteVisibilityTestSuite struct {
	suite.Suite
	db *sql.DB
}

func TestSQLiteVisibilityTestSuite(t *testing.T) {
	suite.Run(t, new(SQLiteVisibilityTestSuite))
}

func (suite *SQLiteVisibilityTestSuite) SetupTest() {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(suite.T(), err)
	suite.db = db

	_, err = db.Exec(`
		CREATE TABLE "RESOURCE_GRANT" (
			DEPLOYMENT_ID   VARCHAR(255) NOT NULL,
			ID              VARCHAR(36) PRIMARY KEY,
			RESOURCE_TYPE   VARCHAR(50) NOT NULL,
			RESOURCE_ID     VARCHAR(36) NOT NULL,
			OWNING_OU_ID    VARCHAR(36) NOT NULL,
			SHARE_STAGE     VARCHAR(7) NOT NULL,
			TARGET_SCOPE    VARCHAR(12) NOT NULL,
			TARGET_OU_ID    VARCHAR(36),
			PARENT_GRANT_ID VARCHAR(36),
			CREATED_AT      TEXT DEFAULT (datetime('now')),
			UPDATED_AT      TEXT DEFAULT (datetime('now'))
		);
		CREATE TABLE "RESOURCE_GRANT_EXCLUSION" (
			DEPLOYMENT_ID  VARCHAR(255) NOT NULL,
			GRANT_ID       VARCHAR(36) NOT NULL,
			EXCLUDED_OU_ID VARCHAR(36) NOT NULL,
			PRIMARY KEY (GRANT_ID, EXCLUDED_OU_ID, DEPLOYMENT_ID)
		);
		CREATE TABLE "RESOURCE_GRANT_EDITABLE_FIELD" (
			DEPLOYMENT_ID VARCHAR(255) NOT NULL,
			GRANT_ID      VARCHAR(36) NOT NULL,
			FIELD_KEY     VARCHAR(100) NOT NULL,
			PRIMARY KEY (GRANT_ID, FIELD_KEY, DEPLOYMENT_ID)
		);
		CREATE TABLE "RESOURCE_OVERLAY" (
			DEPLOYMENT_ID   VARCHAR(255) NOT NULL,
			RESOURCE_TYPE   VARCHAR(50) NOT NULL,
			RESOURCE_ID     VARCHAR(36) NOT NULL,
			OU_ID           VARCHAR(36) NOT NULL,
			FIELDS          TEXT NOT NULL,
			PRIMARY KEY (RESOURCE_TYPE, RESOURCE_ID, OU_ID, DEPLOYMENT_ID)
		);
	`)
	require.NoError(suite.T(), err)
}

func (suite *SQLiteVisibilityTestSuite) TearDownTest() {
	suite.NoError(suite.db.Close())
}

// testDeploymentID is used for every grant inserted in this suite; TestDeploymentIsolation
// queries a different, literal deployment id directly to prove isolation.
const testDeploymentID = "dep1"

func (suite *SQLiteVisibilityTestSuite) insertGrant(grant Grant) {
	_, err := suite.db.Exec(queryCreateGrant.GetQuery("sqlite"),
		grant.ID, string(grant.ResourceType), grant.ResourceID, grant.OwningOUID, string(grant.Stage),
		string(grant.TargetScope), nullableString(grant.TargetOUID), nullableString(grant.ParentGrantID),
		testDeploymentID)
	require.NoError(suite.T(), err)
	for _, excluded := range grant.ExcludedOUIDs {
		_, err := suite.db.Exec(queryInsertGrantExclusion.GetQuery("sqlite"), grant.ID, excluded, testDeploymentID)
		require.NoError(suite.T(), err)
	}
	for _, fieldKey := range grant.EditableFields {
		_, err := suite.db.Exec(queryInsertGrantEditableField.GetQuery("sqlite"), grant.ID, fieldKey, testDeploymentID)
		require.NoError(suite.T(), err)
	}
}

// relevantGrantIDs returns the IDs of every "role" grant buildRelevantGrantsQuery considers
// relevant to chainOUIDs, using the real SQLite driver end to end.
func (suite *SQLiteVisibilityTestSuite) relevantGrantIDs(chainOUIDs []string, deploymentID string) []string {
	query, args := buildRelevantGrantsQuery("role", chainOUIDs, deploymentID)
	rows, err := suite.db.Query(query.GetQuery("sqlite"), args...)
	require.NoError(suite.T(), err)
	defer func() { require.NoError(suite.T(), rows.Close()) }()

	var ids []string
	for rows.Next() {
		var id, resourceType, resourceID, owningOUID, stage, targetScope string
		var targetOUID, parentGrantID sql.NullString
		require.NoError(suite.T(), rows.Scan(
			&id, &resourceType, &resourceID, &owningOUID, &stage, &targetScope, &targetOUID, &parentGrantID))
		ids = append(ids, id)
	}
	return ids
}

func (suite *SQLiteVisibilityTestSuite) TestRelevantGrants_AllRoots_AlwaysReturned() {
	suite.insertGrant(Grant{
		ID: "g1", ResourceType: "role", ResourceID: "role1", OwningOUID: "owner",
		Stage: StageShare, TargetScope: TargetScopeAllRoots,
	})

	// An all_roots grant is a candidate for any chain, since it can apply to any root.
	suite.Equal([]string{"g1"}, suite.relevantGrantIDs([]string{"root1", "child1"}, testDeploymentID))
}

// An all_ous grant must survive the store-side pre-filter for every chain, exactly like all_roots.
// If the SQL dropped it, deployment-wide visibility would silently never resolve, since
// evaluateChainVisibility only ever sees the rows this query returns.
func (suite *SQLiteVisibilityTestSuite) TestRelevantGrants_AllOUs_AlwaysReturned() {
	suite.insertGrant(Grant{
		ID: "g1", ResourceType: "role", ResourceID: "role1", OwningOUID: "owner",
		Stage: StageShare, TargetScope: TargetScopeAllOUs,
	})

	suite.Equal([]string{"g1"}, suite.relevantGrantIDs([]string{"root1", "child1"}, testDeploymentID))
	// Including a chain in a completely unrelated tree, which is the whole point of the scope.
	suite.Equal([]string{"g1"}, suite.relevantGrantIDs([]string{"otherRoot"}, testDeploymentID))
}

func (suite *SQLiteVisibilityTestSuite) TestRelevantGrants_MatchesTargetOUIDInChain() {
	suite.insertGrant(Grant{
		ID: "g1", ResourceType: "role", ResourceID: "role1", OwningOUID: "owner",
		Stage: StageReshare, TargetScope: TargetScopeAllChildren, TargetOUID: "root1",
		ExcludedOUIDs: []string{"excludedChild"},
	})

	suite.Equal([]string{"g1"}, suite.relevantGrantIDs([]string{"root1", "child1"}, testDeploymentID))
	// A chain that never passes through root1 has no reason to fetch this grant.
	suite.Empty(suite.relevantGrantIDs([]string{"otherRoot", "otherChild"}, testDeploymentID))
}

func (suite *SQLiteVisibilityTestSuite) TestRelevantGrants_ExclusionRowsPersistedAlongsideGrant() {
	suite.insertGrant(Grant{
		ID: "g1", ResourceType: "role", ResourceID: "role1", OwningOUID: "owner",
		Stage: StageReshare, TargetScope: TargetScopeAllChildren, TargetOUID: "root1",
		ExcludedOUIDs: []string{"excludedChild", "excludedChild2"},
	})

	ids := suite.relevantGrantIDs([]string{"root1"}, testDeploymentID)
	require.Equal(suite.T(), []string{"g1"}, ids)

	rows, err := suite.db.Query(queryListGrantExclusions.GetQuery("sqlite"), "g1", testDeploymentID)
	require.NoError(suite.T(), err)
	defer func() { require.NoError(suite.T(), rows.Close()) }()
	var excluded []string
	for rows.Next() {
		var id string
		require.NoError(suite.T(), rows.Scan(&id))
		excluded = append(excluded, id)
	}
	suite.ElementsMatch([]string{"excludedChild", "excludedChild2"}, excluded)
}

func (suite *SQLiteVisibilityTestSuite) TestDeploymentIsolation() {
	suite.insertGrant(Grant{
		ID: "g1", ResourceType: "role", ResourceID: "role1", OwningOUID: "owner",
		Stage: StageShare, TargetScope: TargetScopeAllRoots,
	})

	// A different deployment must not see testDeploymentID's grant.
	suite.Empty(suite.relevantGrantIDs([]string{"root1"}, "other-deployment"))
}

// editableFields returns the field keys persisted for grantID, using the real SQLite driver.
func (suite *SQLiteVisibilityTestSuite) editableFields(grantID string) []string {
	rows, err := suite.db.Query(queryListGrantEditableFields.GetQuery("sqlite"), grantID, testDeploymentID)
	require.NoError(suite.T(), err)
	defer func() { require.NoError(suite.T(), rows.Close()) }()

	var keys []string
	for rows.Next() {
		var key string
		require.NoError(suite.T(), rows.Scan(&key))
		keys = append(keys, key)
	}
	return keys
}

func (suite *SQLiteVisibilityTestSuite) TestEditableFields_PersistedAlongsideGrant() {
	suite.insertGrant(Grant{
		ID: "g1", ResourceType: "role", ResourceID: "role1", OwningOUID: "owner",
		Stage: StageShare, TargetScope: TargetScopeAllRoots,
		EditableFields: []string{"assignments.user", "assignments.group"},
	})

	suite.ElementsMatch([]string{"assignments.user", "assignments.group"}, suite.editableFields("g1"))
}

func (suite *SQLiteVisibilityTestSuite) TestEditableFields_EmptyWhenNoneMaterialized() {
	suite.insertGrant(Grant{
		ID: "g1", ResourceType: "role", ResourceID: "role1", OwningOUID: "owner",
		Stage: StageShare, TargetScope: TargetScopeAllRoots,
	})

	suite.Empty(suite.editableFields("g1"))
}

// pagedGrantIDs returns the IDs queryListGrantsForResourcePage yields for one page, using the real
// SQLite driver end to end. Mocked QueryContext tests prove the store passes the right arguments
// but never that the LIMIT/OFFSET placeholders line up with the WHERE-clause ones, which is exactly
// what silently breaks when positional parameters are renumbered.
func (suite *SQLiteVisibilityTestSuite) pagedGrantIDs(resourceID string, limit, offset int) []string {
	rows, err := suite.db.Query(
		queryListGrantsForResourcePage.GetQuery("sqlite"), "role", resourceID, testDeploymentID, limit, offset)
	require.NoError(suite.T(), err)
	defer func() { require.NoError(suite.T(), rows.Close()) }()

	var ids []string
	for rows.Next() {
		var id, resourceType, rID, owningOUID, stage, targetScope string
		var targetOUID, parentGrantID sql.NullString
		require.NoError(suite.T(), rows.Scan(
			&id, &resourceType, &rID, &owningOUID, &stage, &targetScope, &targetOUID, &parentGrantID))
		ids = append(ids, id)
	}
	return ids
}

func (suite *SQLiteVisibilityTestSuite) countGrants(resourceID string) int {
	row := suite.db.QueryRow(queryCountGrantsForResource.GetQuery("sqlite"), "role", resourceID, testDeploymentID)
	var total int
	require.NoError(suite.T(), row.Scan(&total))
	return total
}

// insertPagingGrants inserts five grants for role1 plus one for another role and one in another
// deployment, so the paging assertions also prove the WHERE clause still filters.
//
// The five are inserted in reverse id order deliberately. Every row lands in the same
// second-resolution CREATED_AT, so ordering by CREATED_AT alone leaves SQLite free to fall back on
// insertion (rowid) order — which here is the exact opposite of id order. That makes the ORDER BY's
// ID tiebreak observable: without it the paging assertions below come back reversed.
func (suite *SQLiteVisibilityTestSuite) insertPagingGrants() {
	for _, id := range []string{"g5", "g4", "g3", "g2", "g1"} {
		suite.insertGrant(Grant{
			ID: id, ResourceType: "role", ResourceID: "role1", OwningOUID: "owner",
			Stage: StageShare, TargetScope: TargetScopeRoot, TargetOUID: "root-" + id,
		})
	}
	suite.insertGrant(Grant{
		ID: "other-role", ResourceType: "role", ResourceID: "role2", OwningOUID: "owner",
		Stage: StageShare, TargetScope: TargetScopeAllRoots,
	})
	_, err := suite.db.Exec(queryCreateGrant.GetQuery("sqlite"),
		"other-dep", "role", "role1", "owner", string(StageShare), string(TargetScopeAllRoots),
		nil, nil, "dep2")
	require.NoError(suite.T(), err)
}

func (suite *SQLiteVisibilityTestSuite) TestListGrantsForResourcePage_WalksEveryGrantExactlyOnce() {
	suite.insertPagingGrants()

	// Ids come back in ascending order despite the reverse insertion, so the page boundaries are
	// driven by the ORDER BY rather than by whatever order the rows happen to sit in.
	suite.Equal([]string{"g1", "g2"}, suite.pagedGrantIDs("role1", 2, 0))
	suite.Equal([]string{"g3", "g4"}, suite.pagedGrantIDs("role1", 2, 2))
	suite.Equal([]string{"g5"}, suite.pagedGrantIDs("role1", 2, 4))
	suite.Empty(suite.pagedGrantIDs("role1", 2, 6))
}

func (suite *SQLiteVisibilityTestSuite) TestListGrantsForResourcePage_FiltersResourceAndDeployment() {
	suite.insertPagingGrants()

	// The other role's grant and the other deployment's grant are both excluded.
	suite.Equal([]string{"g1", "g2", "g3", "g4", "g5"}, suite.pagedGrantIDs("role1", 100, 0))
	suite.Equal([]string{"other-role"}, suite.pagedGrantIDs("role2", 100, 0))
}

func (suite *SQLiteVisibilityTestSuite) TestCountGrantsForResource() {
	suite.insertPagingGrants()

	suite.Equal(5, suite.countGrants("role1"))
	suite.Equal(1, suite.countGrants("role2"))
	suite.Equal(0, suite.countGrants("role-with-no-grants"))
}

// Overlay queries against the real driver. Before the single-JSON-column redesign this table had no
// real-SQL coverage at all, so nothing verified that the upsert's ON CONFLICT target actually
// matched the table's primary key — a mismatch fails at execution time, not compile time, and the
// mocked store tests cannot see it.

func (suite *SQLiteVisibilityTestSuite) upsertOverlay(resourceID, ouID, fieldsJSON string) {
	_, err := suite.db.Exec(queryUpsertResourceOverlay.GetQuery("sqlite"),
		"role", resourceID, ouID, fieldsJSON, testDeploymentID)
	require.NoError(suite.T(), err)
}

func (suite *SQLiteVisibilityTestSuite) selectOverlay(resourceID, ouID string) (string, bool) {
	rows, err := suite.db.Query(queryGetResourceOverlay.GetQuery("sqlite"),
		"role", resourceID, ouID, testDeploymentID)
	require.NoError(suite.T(), err)
	defer func() { require.NoError(suite.T(), rows.Close()) }()

	if !rows.Next() {
		return "", false
	}
	var fields string
	require.NoError(suite.T(), rows.Scan(&fields))
	return fields, true
}

func (suite *SQLiteVisibilityTestSuite) TestOverlay_UpsertReplacesTheWholeFieldSet() {
	suite.upsertOverlay("role1", "ou1", `{"assignments":"[\"u1\"]","label":"Ops"}`)
	fields, found := suite.selectOverlay("role1", "ou1")
	suite.True(found)
	suite.JSONEq(`{"assignments":"[\"u1\"]","label":"Ops"}`, fields)

	// The ON CONFLICT target must match the new 4-column primary key: a second write for the same
	// (resource, OU) replaces the row rather than inserting a duplicate or raising a constraint
	// error, and replaces the field set wholesale rather than merging into it.
	suite.upsertOverlay("role1", "ou1", `{"label":"Support"}`)
	fields, found = suite.selectOverlay("role1", "ou1")
	suite.True(found)
	suite.JSONEq(`{"label":"Support"}`, fields)

	var rowCount int
	require.NoError(suite.T(), suite.db.QueryRow(
		`SELECT COUNT(*) FROM "RESOURCE_OVERLAY" WHERE RESOURCE_ID = ? AND OU_ID = ?`,
		"role1", "ou1").Scan(&rowCount))
	suite.Equal(1, rowCount, "a resource/OU pair must never accumulate more than one overlay row")
}

func (suite *SQLiteVisibilityTestSuite) TestOverlay_IsScopedPerResourceOUAndDeployment() {
	suite.upsertOverlay("role1", "ou1", `{"label":"A"}`)
	suite.upsertOverlay("role1", "ou2", `{"label":"B"}`)
	// Same OU, different resource: the primary key spans both, so this is its own row.
	suite.upsertOverlay("role2", "ou1", `{"label":"C"}`)
	_, err := suite.db.Exec(queryUpsertResourceOverlay.GetQuery("sqlite"),
		"role", "role1", "ou1", `{"label":"other-deployment"}`, "dep2")
	require.NoError(suite.T(), err)

	// Each (resource, OU) keeps its own set, and another deployment's row for the same pair is
	// neither returned nor overwritten.
	ou1, _ := suite.selectOverlay("role1", "ou1")
	ou2, _ := suite.selectOverlay("role1", "ou2")
	otherResource, _ := suite.selectOverlay("role2", "ou1")
	suite.JSONEq(`{"label":"A"}`, ou1)
	suite.JSONEq(`{"label":"B"}`, ou2)
	suite.JSONEq(`{"label":"C"}`, otherResource)

	_, found := suite.selectOverlay("role1", "ou-never-written")
	suite.False(found)
}

func (suite *SQLiteVisibilityTestSuite) TestOverlay_DeleteRemovesTheRow() {
	suite.upsertOverlay("role1", "ou1", `{"label":"A"}`)
	suite.upsertOverlay("role1", "ou2", `{"label":"B"}`)
	suite.upsertOverlay("role2", "ou1", `{"label":"C"}`)

	_, err := suite.db.Exec(queryDeleteResourceOverlay.GetQuery("sqlite"),
		"role", "role1", "ou1", testDeploymentID)
	require.NoError(suite.T(), err)

	_, found := suite.selectOverlay("role1", "ou1")
	suite.False(found)
	// Deleting one OU's overlay must not touch another OU's, nor the same OU's on another resource.
	remaining, found := suite.selectOverlay("role1", "ou2")
	suite.True(found)
	suite.JSONEq(`{"label":"B"}`, remaining)
	otherResource, found := suite.selectOverlay("role2", "ou1")
	suite.True(found)
	suite.JSONEq(`{"label":"C"}`, otherResource)
}
