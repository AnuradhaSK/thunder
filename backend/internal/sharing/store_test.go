// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package sharing

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/tests/mocks/database/providermock"
)

const testStoreDeploymentID = "test-deployment-id"

// StoreTestSuite tests the sharingStore DB-backed implementation.
type StoreTestSuite struct {
	suite.Suite
	mockDBProvider *providermock.DBProviderInterfaceMock
	mockDBClient   *providermock.DBClientInterfaceMock
	store          *sharingStore
}

func TestStoreTestSuite(t *testing.T) {
	suite.Run(t, new(StoreTestSuite))
}

func (suite *StoreTestSuite) SetupTest() {
	suite.mockDBProvider = providermock.NewDBProviderInterfaceMock(suite.T())
	suite.mockDBClient = providermock.NewDBClientInterfaceMock(suite.T())
	suite.store = &sharingStore{
		dbProvider:   suite.mockDBProvider,
		deploymentID: testStoreDeploymentID,
	}
}

func (suite *StoreTestSuite) TestCreateGrant() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("ExecuteContext", mock.Anything, queryCreateGrant,
		"grant1", "role", "role1", "owner-ou", "share", "root", "root1", nil, testStoreDeploymentID,
	).Return(int64(1), nil)

	err := suite.store.CreateGrant(context.Background(), Grant{
		ID: "grant1", ResourceType: "role", ResourceID: "role1", OwningOUID: "owner-ou",
		Stage: StageShare, TargetScope: TargetScopeRoot, TargetOUID: "root1",
	})

	suite.NoError(err)
}

// TestCreateGrant_WithExclusions parallels TestCreateGrant_WithEditableFields below with a
// different row set; the near-identical structure is expected, not accidental duplication.
func (suite *StoreTestSuite) TestCreateGrant_WithExclusions() { //nolint:dupl
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("ExecuteContext", mock.Anything, queryCreateGrant,
		"grant1", "role", "role1", "owner-ou", "share", "all_roots", nil, nil, testStoreDeploymentID,
	).Return(int64(1), nil)
	suite.mockDBClient.On("ExecuteContext", mock.Anything, queryInsertGrantExclusion,
		"grant1", "excluded1", testStoreDeploymentID).Return(int64(1), nil)
	suite.mockDBClient.On("ExecuteContext", mock.Anything, queryInsertGrantExclusion,
		"grant1", "excluded2", testStoreDeploymentID).Return(int64(1), nil)

	err := suite.store.CreateGrant(context.Background(), Grant{
		ID: "grant1", ResourceType: "role", ResourceID: "role1", OwningOUID: "owner-ou",
		Stage: StageShare, TargetScope: TargetScopeAllRoots,
		// Duplicate "excluded1" must be inserted only once.
		ExcludedOUIDs: []string{"excluded1", "excluded2", "excluded1"},
	})

	suite.NoError(err)
	suite.mockDBClient.AssertNumberOfCalls(suite.T(), "ExecuteContext", 3)
}

func (suite *StoreTestSuite) TestCreateGrant_ExclusionInsertError() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("ExecuteContext", mock.Anything, queryCreateGrant,
		"grant1", "role", "role1", "owner-ou", "share", "all_roots", nil, nil, testStoreDeploymentID,
	).Return(int64(1), nil)
	suite.mockDBClient.On("ExecuteContext", mock.Anything, queryInsertGrantExclusion,
		"grant1", "excluded1", testStoreDeploymentID).Return(int64(0), errors.New("insert failed"))

	err := suite.store.CreateGrant(context.Background(), Grant{
		ID: "grant1", ResourceType: "role", ResourceID: "role1", OwningOUID: "owner-ou",
		Stage: StageShare, TargetScope: TargetScopeAllRoots, ExcludedOUIDs: []string{"excluded1"},
	})

	suite.Error(err)
}

func (suite *StoreTestSuite) TestCreateGrant_WithEditableFields() { //nolint:dupl
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("ExecuteContext", mock.Anything, queryCreateGrant,
		"grant1", "role", "role1", "owner-ou", "share", "all_roots", nil, nil, testStoreDeploymentID,
	).Return(int64(1), nil)
	suite.mockDBClient.On("ExecuteContext", mock.Anything, queryInsertGrantEditableField,
		"grant1", "assignments.user", testStoreDeploymentID).Return(int64(1), nil)
	suite.mockDBClient.On("ExecuteContext", mock.Anything, queryInsertGrantEditableField,
		"grant1", "assignments.group", testStoreDeploymentID).Return(int64(1), nil)

	err := suite.store.CreateGrant(context.Background(), Grant{
		ID: "grant1", ResourceType: "role", ResourceID: "role1", OwningOUID: "owner-ou",
		Stage: StageShare, TargetScope: TargetScopeAllRoots,
		// Duplicate "assignments.user" must be inserted only once.
		EditableFields: []string{"assignments.user", "assignments.group", "assignments.user"},
	})

	suite.NoError(err)
	suite.mockDBClient.AssertNumberOfCalls(suite.T(), "ExecuteContext", 3)
}

func (suite *StoreTestSuite) TestCreateGrant_EditableFieldInsertError() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("ExecuteContext", mock.Anything, queryCreateGrant,
		"grant1", "role", "role1", "owner-ou", "share", "all_roots", nil, nil, testStoreDeploymentID,
	).Return(int64(1), nil)
	suite.mockDBClient.On("ExecuteContext", mock.Anything, queryInsertGrantEditableField,
		"grant1", "assignments", testStoreDeploymentID).Return(int64(0), errors.New("insert failed"))

	err := suite.store.CreateGrant(context.Background(), Grant{
		ID: "grant1", ResourceType: "role", ResourceID: "role1", OwningOUID: "owner-ou",
		Stage: StageShare, TargetScope: TargetScopeAllRoots, EditableFields: []string{"assignments"},
	})

	suite.Error(err)
}

func (suite *StoreTestSuite) TestGetGrant_NotFound() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryGetGrantByID, "missing", testStoreDeploymentID).
		Return([]map[string]interface{}{}, nil)

	_, err := suite.store.GetGrant(context.Background(), "missing")

	suite.ErrorIs(err, ErrGrantNotFound)
}

func (suite *StoreTestSuite) TestGetGrant_Found() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryGetGrantByID, "grant1", testStoreDeploymentID).
		Return([]map[string]interface{}{
			{
				"id": "grant1", "resource_type": "role", "resource_id": "role1",
				"owning_ou_id": "owner-ou", "share_stage": "reshare", "target_scope": "ou",
				"target_ou_id": "ou1", "parent_grant_id": "parent1",
			},
		}, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryListGrantExclusions, "grant1", testStoreDeploymentID).
		Return([]map[string]interface{}{}, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryListGrantEditableFields, "grant1", testStoreDeploymentID).
		Return([]map[string]interface{}{}, nil)

	grant, err := suite.store.GetGrant(context.Background(), "grant1")

	suite.NoError(err)
	suite.Equal(Grant{
		ID: "grant1", ResourceType: "role", ResourceID: "role1", OwningOUID: "owner-ou",
		Stage: StageReshare, TargetScope: TargetScopeOU, TargetOUID: "ou1", ParentGrantID: "parent1",
		ExcludedOUIDs: []string{}, EditableFields: []string{},
	}, grant)
}

func (suite *StoreTestSuite) TestGetGrant_LoadsExclusions() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryGetGrantByID, "grant1", testStoreDeploymentID).
		Return([]map[string]interface{}{
			{
				"id": "grant1", "resource_type": "role", "resource_id": "role1",
				"owning_ou_id": "owner-ou", "share_stage": "share", "target_scope": "all_roots",
				"target_ou_id": nil, "parent_grant_id": nil,
			},
		}, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryListGrantExclusions, "grant1", testStoreDeploymentID).
		Return([]map[string]interface{}{{"excluded_ou_id": "excluded1"}, {"excluded_ou_id": "excluded2"}}, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryListGrantEditableFields, "grant1", testStoreDeploymentID).
		Return([]map[string]interface{}{}, nil)

	grant, err := suite.store.GetGrant(context.Background(), "grant1")

	suite.NoError(err)
	suite.Equal([]string{"excluded1", "excluded2"}, grant.ExcludedOUIDs)
}

func (suite *StoreTestSuite) TestGetGrant_LoadsEditableFields() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryGetGrantByID, "grant1", testStoreDeploymentID).
		Return([]map[string]interface{}{
			{
				"id": "grant1", "resource_type": "role", "resource_id": "role1",
				"owning_ou_id": "owner-ou", "share_stage": "share", "target_scope": "all_roots",
				"target_ou_id": nil, "parent_grant_id": nil,
			},
		}, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryListGrantExclusions, "grant1", testStoreDeploymentID).
		Return([]map[string]interface{}{}, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryListGrantEditableFields, "grant1", testStoreDeploymentID).
		Return([]map[string]interface{}{{"field_key": "assignments.user"}, {"field_key": "assignments.group"}}, nil)

	grant, err := suite.store.GetGrant(context.Background(), "grant1")

	suite.NoError(err)
	suite.Equal([]string{"assignments.user", "assignments.group"}, grant.EditableFields)
}

func (suite *StoreTestSuite) TestGetGrant_NullableColumnsAbsent() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryGetGrantByID, "grant1", testStoreDeploymentID).
		Return([]map[string]interface{}{
			{
				"id": "grant1", "resource_type": "role", "resource_id": "role1",
				"owning_ou_id": "owner-ou", "share_stage": "share", "target_scope": "all_roots",
				"target_ou_id": nil, "parent_grant_id": nil,
			},
		}, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryListGrantExclusions, "grant1", testStoreDeploymentID).
		Return([]map[string]interface{}{}, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryListGrantEditableFields, "grant1", testStoreDeploymentID).
		Return([]map[string]interface{}{}, nil)

	grant, err := suite.store.GetGrant(context.Background(), "grant1")

	suite.NoError(err)
	suite.Equal("", grant.TargetOUID)
	suite.Equal("", grant.ParentGrantID)
}

func (suite *StoreTestSuite) TestGetGrant_MalformedRow() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryGetGrantByID, "grant1", testStoreDeploymentID).
		Return([]map[string]interface{}{{"id": "grant1"}}, nil)

	_, err := suite.store.GetGrant(context.Background(), "grant1")

	suite.Error(err)
}

func (suite *StoreTestSuite) TestDeleteGrant() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("ExecuteContext", mock.Anything, queryDeleteGrant, "grant1", testStoreDeploymentID).
		Return(int64(1), nil)

	suite.NoError(suite.store.DeleteGrant(context.Background(), "grant1"))
}

func (suite *StoreTestSuite) TestListGrantsForResource() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryListGrantsForResource,
		"role", "role1", testStoreDeploymentID).
		Return([]map[string]interface{}{
			{
				"id": "g1", "resource_type": "role", "resource_id": "role1", "owning_ou_id": "ou1",
				"share_stage": "share", "target_scope": "all_roots", "target_ou_id": nil, "parent_grant_id": nil,
			},
		}, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryListGrantExclusions, "g1", testStoreDeploymentID).
		Return([]map[string]interface{}{{"excluded_ou_id": "excluded1"}}, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryListGrantEditableFields, "g1", testStoreDeploymentID).
		Return([]map[string]interface{}{}, nil)

	grants, err := suite.store.ListGrantsForResource(context.Background(), "role", "role1")

	suite.NoError(err)
	suite.Len(grants, 1)
	suite.Equal([]string{"excluded1"}, grants[0].ExcludedOUIDs)
}

func (suite *StoreTestSuite) TestListChildGrants() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryListChildGrants, "parent1", testStoreDeploymentID).
		Return([]map[string]interface{}{}, nil)

	grants, err := suite.store.ListChildGrants(context.Background(), "parent1")

	suite.NoError(err)
	suite.Empty(grants)
}

func (suite *StoreTestSuite) TestListGrantsRelevantToChain() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, mock.AnythingOfType("model.DBQuery"),
		testStoreDeploymentID, "role", "root1", "ou1").
		Return([]map[string]interface{}{
			{
				"id": "g1", "resource_type": "role", "resource_id": "role1", "owning_ou_id": "owner-ou",
				"share_stage": "share", "target_scope": "all_roots", "target_ou_id": nil, "parent_grant_id": nil,
			},
		}, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryListGrantExclusions, "g1", testStoreDeploymentID).
		Return([]map[string]interface{}{}, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryListGrantEditableFields, "g1", testStoreDeploymentID).
		Return([]map[string]interface{}{}, nil)

	grants, err := suite.store.ListGrantsRelevantToChain(context.Background(), "role", []string{"root1", "ou1"})

	suite.NoError(err)
	suite.Len(grants, 1)
	suite.Equal("role1", grants[0].ResourceID)
}

func (suite *StoreTestSuite) TestListGrantsRelevantToChain_NoMatch() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, mock.AnythingOfType("model.DBQuery"),
		testStoreDeploymentID, "role", "root1", "ou1").
		Return([]map[string]interface{}{}, nil)

	grants, err := suite.store.ListGrantsRelevantToChain(context.Background(), "role", []string{"root1", "ou1"})

	suite.NoError(err)
	suite.Empty(grants)
}

func (suite *StoreTestSuite) TestOverlay_GetSetDelete() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)

	// One row per (resource, OU) now holds every field key, so a read returns the whole set.
	suite.mockDBClient.On("QueryContext", mock.Anything, queryGetResourceOverlay,
		"role", "role1", "ou1", testStoreDeploymentID).
		Return([]map[string]interface{}{{"fields": `{"assignments":"[\"u1\"]","label":"Ops"}`}}, nil).Once()
	fields, found, err := suite.store.GetOverlay(context.Background(), "role", "role1", "ou1")
	suite.NoError(err)
	suite.True(found)
	suite.Equal(map[string]string{"assignments": `["u1"]`, "label": "Ops"}, fields)

	suite.mockDBClient.On("QueryContext", mock.Anything, queryGetResourceOverlay,
		"role", "role1", "ou-none", testStoreDeploymentID).
		Return([]map[string]interface{}{}, nil).Once()
	_, found, err = suite.store.GetOverlay(context.Background(), "role", "role1", "ou-none")
	suite.NoError(err)
	suite.False(found)

	suite.mockDBClient.On("ExecuteContext", mock.Anything, queryUpsertResourceOverlay,
		"role", "role1", "ou1", `{"assignments":"[\"u1\",\"u2\"]"}`, testStoreDeploymentID).
		Return(int64(1), nil)
	suite.NoError(suite.store.SetOverlay(context.Background(), "role", "role1", "ou1",
		map[string]string{"assignments": `["u1","u2"]`}))

	suite.mockDBClient.On("ExecuteContext", mock.Anything, queryDeleteResourceOverlay,
		"role", "role1", "ou1", testStoreDeploymentID).
		Return(int64(1), nil)
	suite.NoError(suite.store.DeleteOverlay(context.Background(), "role", "role1", "ou1"))
}

// TestGetOverlay_AcceptsByteColumn proves the FIELDS column decodes when the driver hands it back
// as []byte, which is how Postgres' JSONB arrives. The previous row-per-field reader asserted a
// bare string and would have failed there; only SQLite's TEXT ever satisfied it.
func (suite *StoreTestSuite) TestGetOverlay_AcceptsByteColumn() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryGetResourceOverlay,
		"role", "role1", "ou1", testStoreDeploymentID).
		Return([]map[string]interface{}{{"fields": []byte(`{"assignments":"v"}`)}}, nil).Once()

	fields, found, err := suite.store.GetOverlay(context.Background(), "role", "role1", "ou1")

	suite.NoError(err)
	suite.True(found)
	suite.Equal(map[string]string{"assignments": "v"}, fields)
}

// TestGetOverlay_EmptyObjectIsARowWithNoOverrides distinguishes the two states the row-per-field
// shape could not express: an OU with an overlay that overrides nothing, versus no overlay at all.
func (suite *StoreTestSuite) TestGetOverlay_EmptyObjectIsARowWithNoOverrides() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryGetResourceOverlay,
		"role", "role1", "ou1", testStoreDeploymentID).
		Return([]map[string]interface{}{{"fields": "{}"}}, nil).Once()

	fields, found, err := suite.store.GetOverlay(context.Background(), "role", "role1", "ou1")

	suite.NoError(err)
	suite.True(found, "a row exists, so found is true even though it overrides nothing")
	suite.Empty(fields)
}

// TestGetOverlay_MalformedJSONErrors proves a corrupt FIELDS column fails loudly. Degrading to an
// empty set would silently serve the owner's values to a sharee that had overridden them.
func (suite *StoreTestSuite) TestGetOverlay_MalformedJSONErrors() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryGetResourceOverlay,
		"role", "role1", "ou1", testStoreDeploymentID).
		Return([]map[string]interface{}{{"fields": "not json"}}, nil).Once()

	_, _, err := suite.store.GetOverlay(context.Background(), "role", "role1", "ou1")

	suite.Error(err)
}

// TestSetOverlay_NilFieldsStoresEmptyObject proves the NOT NULL column always receives valid JSON.
func (suite *StoreTestSuite) TestSetOverlay_NilFieldsStoresEmptyObject() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("ExecuteContext", mock.Anything, queryUpsertResourceOverlay,
		"role", "role1", "ou1", "{}", testStoreDeploymentID).
		Return(int64(1), nil)

	suite.NoError(suite.store.SetOverlay(context.Background(), "role", "role1", "ou1", nil))
}

func (suite *StoreTestSuite) TestListEditableFields() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("QueryContext", mock.Anything, queryListGrantEditableFields, "grant1", testStoreDeploymentID).
		Return([]map[string]interface{}{{"field_key": "assignments"}}, nil)

	fields, err := suite.store.listEditableFields(context.Background(), "grant1")

	suite.NoError(err)
	suite.Equal([]string{"assignments"}, fields)
}

func (suite *StoreTestSuite) TestListEditableFields_ProviderError() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(nil, errors.New("db unavailable"))

	_, err := suite.store.listEditableFields(context.Background(), "grant1")

	suite.Error(err)
}

func (suite *StoreTestSuite) TestCreateGrant_ProviderError() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(nil, errors.New("db unavailable"))

	err := suite.store.CreateGrant(context.Background(), Grant{ID: "grant1"})

	suite.Error(err)
}

func (suite *StoreTestSuite) TestCreateGrant_ExecuteError() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(suite.mockDBClient, nil)
	suite.mockDBClient.On("ExecuteContext", mock.Anything, queryCreateGrant,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything,
	).Return(int64(0), errors.New("insert failed"))

	err := suite.store.CreateGrant(context.Background(), Grant{ID: "grant1"})

	suite.Error(err)
}

func (suite *StoreTestSuite) TestDeleteGrant_ProviderError() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(nil, errors.New("db unavailable"))

	err := suite.store.DeleteGrant(context.Background(), "grant1")

	suite.Error(err)
}

func (suite *StoreTestSuite) TestListGrantsForResource_ProviderError() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(nil, errors.New("db unavailable"))

	_, err := suite.store.ListGrantsForResource(context.Background(), "role", "role1")

	suite.Error(err)
}

func (suite *StoreTestSuite) TestSetOverlay_ProviderError() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(nil, errors.New("db unavailable"))

	err := suite.store.SetOverlay(context.Background(), "role", "role1", "ou1", map[string]string{"k": "v"})

	suite.Error(err)
}

func (suite *StoreTestSuite) TestDeleteOverlay_ProviderError() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(nil, errors.New("db unavailable"))

	err := suite.store.DeleteOverlay(context.Background(), "role", "role1", "ou1")

	suite.Error(err)
}

func (suite *StoreTestSuite) TestGetConfigDBClient_PropagatesProviderError() {
	suite.mockDBProvider.On("GetConfigDBClient").Return(nil, errors.New("db unavailable"))

	_, err := suite.store.GetGrant(context.Background(), "grant1")

	suite.Error(err)
}

func TestParseBool(t *testing.T) {
	cases := []struct {
		name    string
		value   interface{}
		want    bool
		wantErr bool
	}{
		{"bool true", true, true, false},
		{"bool false", false, false, false},
		{"int64 nonzero", int64(1), true, false},
		{"int64 zero", int64(0), false, false},
		{"float64 nonzero", float64(1), true, false},
		{"string true", "true", true, false},
		{"string 1", "1", true, false},
		{"string other", "nope", false, false},
		{"nil", nil, false, true},
		{"unsupported type", []int{1}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseBool(tc.value, "editable")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNullableString(t *testing.T) {
	if nullableString("") != nil {
		t.Fatal("empty string should become nil")
	}
	if nullableString("x") != "x" {
		t.Fatal("non-empty string should pass through unchanged")
	}
}

func TestNullableStringField(t *testing.T) {
	if nullableStringField(nil) != "" {
		t.Fatal("nil column should become empty string")
	}
	if nullableStringField("x") != "x" {
		t.Fatal("non-nil string column should pass through unchanged")
	}
}
