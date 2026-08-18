// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package sharing

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/thunder-id/thunderid/internal/system/config"
	"github.com/thunder-id/thunderid/internal/system/database/provider"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

var getDBProvider = provider.GetDBProvider

// sharingStoreInterface defines the storage operations backing the generic sharing framework.
// A single store implementation serves every resource type — no per-resource-type tables or
// methods are added here; resourceType is always a plain data parameter.
type sharingStoreInterface interface {
	CreateGrant(ctx context.Context, grant Grant) error
	GetGrant(ctx context.Context, id string) (Grant, error)
	DeleteGrant(ctx context.Context, id string) error
	ListGrantsForResource(ctx context.Context, resourceType ResourceType, resourceID string) ([]Grant, error)

	// ListGrantsForResourcePage returns one page of a resource's grants, and CountGrantsForResource
	// the total behind it. These back the admin/audit list endpoint only. Callers that reason over
	// the grant graph as a whole — ExportGrants' dependency ordering, and resolveNearestGrant's
	// chain evaluation — must keep using the unbounded ListGrantsForResource: a truncated grant set
	// silently produces a partial export, or a wrong visibility answer.
	ListGrantsForResourcePage(
		ctx context.Context, resourceType ResourceType, resourceID string, limit, offset int,
	) ([]Grant, error)
	CountGrantsForResource(ctx context.Context, resourceType ResourceType, resourceID string) (int, error)

	ListChildGrants(ctx context.Context, parentGrantID string) ([]Grant, error)

	// ListGrantsRelevantToChain returns every grant of resourceType (across every resource of that
	// type) whose TargetScope is all_roots (which can apply to any root) or whose TargetOUID is
	// one of chainOUIDs, each with its exclusion list hydrated. The caller (service.go) evaluates
	// actual chain-by-chain coverage in memory via evaluateChainVisibility — this method performs
	// no tree traversal or coverage logic itself, only the bounded row fetch.
	ListGrantsRelevantToChain(
		ctx context.Context, resourceType ResourceType, chainOUIDs []string,
	) ([]Grant, error)

	// GetOverlay returns ouID's whole templated-field override set for a resource, decoded from the
	// single JSON object the row stores, plus whether a row exists at all. SetOverlay replaces that
	// set wholesale, and DeleteOverlay drops the row. The unit throughout is the whole set, not one
	// field: a per-field write is a read-modify-write at the caller.
	GetOverlay(
		ctx context.Context, resourceType ResourceType, resourceID, ouID string,
	) (map[string]string, bool, error)
	SetOverlay(
		ctx context.Context, resourceType ResourceType, resourceID, ouID string, fields map[string]string,
	) error
	DeleteOverlay(ctx context.Context, resourceType ResourceType, resourceID, ouID string) error
}

// sharingStore is the default DB-backed implementation of sharingStoreInterface.
type sharingStore struct {
	dbProvider   provider.DBProviderInterface
	deploymentID string
}

// newSharingStore creates a new sharingStore and its transactioner.
func newSharingStore() (sharingStoreInterface, providers.Transactioner, error) {
	dbProvider := getDBProvider()
	client, err := dbProvider.GetConfigDBClient()
	if err != nil {
		return nil, nil, err
	}
	transactioner, err := client.GetTransactioner()
	if err != nil {
		return nil, nil, err
	}
	return &sharingStore{
		dbProvider:   dbProvider,
		deploymentID: config.GetServerRuntime().Config.Server.Identifier,
	}, transactioner, nil
}

func (s *sharingStore) getConfigDBClient() (provider.DBClientInterface, error) {
	dbClient, err := s.dbProvider.GetConfigDBClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get database client: %w", err)
	}
	return dbClient, nil
}

// CreateGrant inserts a new grant and, if grant.ExcludedOUIDs is non-empty, its exclusion
// rows.
func (s *sharingStore) CreateGrant(ctx context.Context, grant Grant) error {
	dbClient, err := s.getConfigDBClient()
	if err != nil {
		return err
	}
	_, err = dbClient.ExecuteContext(ctx, queryCreateGrant,
		grant.ID, string(grant.ResourceType), grant.ResourceID, grant.OwningOUID, string(grant.Stage),
		string(grant.TargetScope), nullableString(grant.TargetOUID), nullableString(grant.ParentGrantID),
		s.deploymentID)
	if err != nil {
		return fmt.Errorf("failed to create grant: %w", err)
	}
	for _, excludedOUID := range dedupeStrings(grant.ExcludedOUIDs) {
		if _, err := dbClient.ExecuteContext(
			ctx, queryInsertGrantExclusion, grant.ID, excludedOUID, s.deploymentID); err != nil {
			return fmt.Errorf("failed to create grant exclusion: %w", err)
		}
	}
	for _, fieldKey := range dedupeStrings(grant.EditableFields) {
		if _, err := dbClient.ExecuteContext(
			ctx, queryInsertGrantEditableField, grant.ID, fieldKey, s.deploymentID); err != nil {
			return fmt.Errorf("failed to create grant editable field: %w", err)
		}
	}
	return nil
}

// GetGrant retrieves a grant by id, including its exclusion list.
func (s *sharingStore) GetGrant(ctx context.Context, id string) (Grant, error) {
	dbClient, err := s.getConfigDBClient()
	if err != nil {
		return Grant{}, err
	}
	results, err := dbClient.QueryContext(ctx, queryGetGrantByID, id, s.deploymentID)
	if err != nil {
		return Grant{}, fmt.Errorf("failed to get grant: %w", err)
	}
	if len(results) == 0 {
		return Grant{}, ErrGrantNotFound
	}
	grant, err := buildGrantFromRow(results[0])
	if err != nil {
		return Grant{}, err
	}
	if grant.ExcludedOUIDs, err = s.listExclusions(ctx, grant.ID); err != nil {
		return Grant{}, err
	}
	if grant.EditableFields, err = s.listEditableFields(ctx, grant.ID); err != nil {
		return Grant{}, err
	}
	return grant, nil
}

// DeleteGrant deletes a grant by id. Dependent reshare grants are removed by the
// database's ON DELETE CASCADE on PARENT_GRANT_ID.
func (s *sharingStore) DeleteGrant(ctx context.Context, id string) error {
	dbClient, err := s.getConfigDBClient()
	if err != nil {
		return err
	}
	if _, err := dbClient.ExecuteContext(ctx, queryDeleteGrant, id, s.deploymentID); err != nil {
		return fmt.Errorf("failed to delete grant: %w", err)
	}
	return nil
}

// ListGrantsForResource lists every grant for a given resource, each with its exclusion list.
func (s *sharingStore) ListGrantsForResource(
	ctx context.Context, resourceType ResourceType, resourceID string,
) ([]Grant, error) {
	dbClient, err := s.getConfigDBClient()
	if err != nil {
		return nil, err
	}
	results, err := dbClient.QueryContext(
		ctx, queryListGrantsForResource, string(resourceType), resourceID, s.deploymentID)
	if err != nil {
		return nil, fmt.Errorf("failed to list grants: %w", err)
	}
	grants, err := buildGrantsFromRows(results)
	if err != nil {
		return nil, err
	}
	return s.hydrateGrantDetails(ctx, grants)
}

// ListGrantsForResourcePage lists one page of a resource's grants, each with its exclusion
// list and editable fields hydrated.
func (s *sharingStore) ListGrantsForResourcePage(
	ctx context.Context, resourceType ResourceType, resourceID string, limit, offset int,
) ([]Grant, error) {
	dbClient, err := s.getConfigDBClient()
	if err != nil {
		return nil, err
	}
	results, err := dbClient.QueryContext(
		ctx, queryListGrantsForResourcePage, string(resourceType), resourceID, s.deploymentID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list grants page: %w", err)
	}
	grants, err := buildGrantsFromRows(results)
	if err != nil {
		return nil, err
	}
	return s.hydrateGrantDetails(ctx, grants)
}

// CountGrantsForResource returns the total number of grants recorded for a resource.
func (s *sharingStore) CountGrantsForResource(
	ctx context.Context, resourceType ResourceType, resourceID string,
) (int, error) {
	dbClient, err := s.getConfigDBClient()
	if err != nil {
		return 0, err
	}
	results, err := dbClient.QueryContext(
		ctx, queryCountGrantsForResource, string(resourceType), resourceID, s.deploymentID)
	if err != nil {
		return 0, fmt.Errorf("failed to count grants: %w", err)
	}
	if len(results) == 0 {
		return 0, nil
	}
	total, ok := results[0]["total"].(int64)
	if !ok {
		return 0, fmt.Errorf("failed to parse total from grant count result")
	}
	return int(total), nil
}

// ListChildGrants lists reshare grants that derive from the given parent grant, each with
// its exclusion list.
func (s *sharingStore) ListChildGrants(ctx context.Context, parentGrantID string) ([]Grant, error) {
	dbClient, err := s.getConfigDBClient()
	if err != nil {
		return nil, err
	}
	results, err := dbClient.QueryContext(ctx, queryListChildGrants, parentGrantID, s.deploymentID)
	if err != nil {
		return nil, fmt.Errorf("failed to list child grants: %w", err)
	}
	grants, err := buildGrantsFromRows(results)
	if err != nil {
		return nil, err
	}
	return s.hydrateGrantDetails(ctx, grants)
}

// ListGrantsRelevantToChain returns every grant of resourceType whose TargetScope is all_roots or
// whose TargetOUID is one of chainOUIDs, each with its exclusion list hydrated.
func (s *sharingStore) ListGrantsRelevantToChain(
	ctx context.Context, resourceType ResourceType, chainOUIDs []string,
) ([]Grant, error) {
	dbClient, err := s.getConfigDBClient()
	if err != nil {
		return nil, err
	}
	query, args := buildRelevantGrantsQuery(resourceType, chainOUIDs, s.deploymentID)
	results, err := dbClient.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list grants relevant to OU chain: %w", err)
	}
	grants, err := buildGrantsFromRows(results)
	if err != nil {
		return nil, err
	}
	return s.hydrateGrantDetails(ctx, grants)
}

// GetOverlay retrieves an OU's whole templated-field override set for a resource.
func (s *sharingStore) GetOverlay(
	ctx context.Context, resourceType ResourceType, resourceID, ouID string,
) (map[string]string, bool, error) {
	dbClient, err := s.getConfigDBClient()
	if err != nil {
		return nil, false, err
	}
	results, err := dbClient.QueryContext(ctx, queryGetResourceOverlay,
		string(resourceType), resourceID, ouID, s.deploymentID)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get resource overlay: %w", err)
	}
	if len(results) == 0 {
		return nil, false, nil
	}
	fields, err := parseOverlayFields(results[0]["fields"])
	if err != nil {
		return nil, false, err
	}
	return fields, true, nil
}

// SetOverlay replaces an OU's whole templated-field override set for a resource. An empty or nil
// set is stored as an empty JSON object rather than deleting the row: "this OU has overridden
// nothing" and "this OU has no overlay at all" are different states, and only DeleteOverlay
// produces the latter.
func (s *sharingStore) SetOverlay(
	ctx context.Context, resourceType ResourceType, resourceID, ouID string, fields map[string]string,
) error {
	dbClient, err := s.getConfigDBClient()
	if err != nil {
		return err
	}
	encoded, err := encodeOverlayFields(fields)
	if err != nil {
		return err
	}
	_, err = dbClient.ExecuteContext(ctx, queryUpsertResourceOverlay,
		string(resourceType), resourceID, ouID, encoded, s.deploymentID)
	if err != nil {
		return fmt.Errorf("failed to set resource overlay: %w", err)
	}
	return nil
}

// DeleteOverlay removes an OU's whole templated-field override set for a resource.
func (s *sharingStore) DeleteOverlay(
	ctx context.Context, resourceType ResourceType, resourceID, ouID string,
) error {
	dbClient, err := s.getConfigDBClient()
	if err != nil {
		return err
	}
	_, err = dbClient.ExecuteContext(ctx, queryDeleteResourceOverlay,
		string(resourceType), resourceID, ouID, s.deploymentID)
	if err != nil {
		return fmt.Errorf("failed to delete resource overlay: %w", err)
	}
	return nil
}

// parseOverlayFields decodes the FIELDS column into the field-key -> value map it holds. The column
// arrives as a string under SQLite and as []byte from Postgres' JSONB, so both are accepted, as
// every other JSON column reader in this codebase does. Malformed JSON is an error rather than an
// empty set: an overlay that silently read as "no overrides" would serve the owner's values to a
// sharee that had overridden them.
func parseOverlayFields(column interface{}) (map[string]string, error) {
	var raw []byte
	switch v := column.(type) {
	case string:
		raw = []byte(v)
	case []byte:
		raw = v
	case nil:
		return map[string]string{}, nil
	default:
		return nil, fmt.Errorf("failed to parse overlay fields as string or []byte, got type: %T", column)
	}
	if len(raw) == 0 {
		return map[string]string{}, nil
	}

	fields := map[string]string{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("failed to unmarshal overlay fields: %w", err)
	}
	return fields, nil
}

// encodeOverlayFields marshals a field-key -> value map for the FIELDS column, normalizing nil to
// an empty JSON object so the NOT NULL column always holds valid JSON.
func encodeOverlayFields(fields map[string]string) (string, error) {
	if fields == nil {
		fields = map[string]string{}
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		return "", fmt.Errorf("failed to marshal overlay fields: %w", err)
	}
	return string(encoded), nil
}

// nullableString converts an empty string to nil so optional columns (TARGET_OU_ID,
// PARENT_GRANT_ID) are stored as SQL NULL rather than an empty string.
func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// buildGrantsFromRows converts multiple result rows into Grant values.
func buildGrantsFromRows(results []map[string]interface{}) ([]Grant, error) {
	grants := make([]Grant, 0, len(results))
	for _, row := range results {
		grant, err := buildGrantFromRow(row)
		if err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	return grants, nil
}

// buildGrantFromRow converts a single result row into a Grant.
func buildGrantFromRow(row map[string]interface{}) (Grant, error) {
	id, ok := row["id"].(string)
	if !ok {
		return Grant{}, fmt.Errorf("failed to parse id as string")
	}
	resourceType, ok := row["resource_type"].(string)
	if !ok {
		return Grant{}, fmt.Errorf("failed to parse resource_type as string")
	}
	resourceID, ok := row["resource_id"].(string)
	if !ok {
		return Grant{}, fmt.Errorf("failed to parse resource_id as string")
	}
	owningOUID, ok := row["owning_ou_id"].(string)
	if !ok {
		return Grant{}, fmt.Errorf("failed to parse owning_ou_id as string")
	}
	stage, ok := row["share_stage"].(string)
	if !ok {
		return Grant{}, fmt.Errorf("failed to parse share_stage as string")
	}
	targetScope, ok := row["target_scope"].(string)
	if !ok {
		return Grant{}, fmt.Errorf("failed to parse target_scope as string")
	}

	return Grant{
		ID:            id,
		ResourceType:  ResourceType(resourceType),
		ResourceID:    resourceID,
		OwningOUID:    owningOUID,
		Stage:         Stage(stage),
		TargetScope:   TargetScope(targetScope),
		TargetOUID:    nullableStringField(row["target_ou_id"]),
		ParentGrantID: nullableStringField(row["parent_grant_id"]),
	}, nil
}

// listExclusions retrieves the exclusion list for a single grant.
func (s *sharingStore) listExclusions(ctx context.Context, grantID string) ([]string, error) {
	dbClient, err := s.getConfigDBClient()
	if err != nil {
		return nil, err
	}
	results, err := dbClient.QueryContext(ctx, queryListGrantExclusions, grantID, s.deploymentID)
	if err != nil {
		return nil, fmt.Errorf("failed to list grant exclusions: %w", err)
	}
	ids := make([]string, 0, len(results))
	for _, row := range results {
		if id, ok := row["excluded_ou_id"].(string); ok {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// listEditableFields retrieves a single grant's materialized editable field keys.
func (s *sharingStore) listEditableFields(ctx context.Context, grantID string) ([]string, error) {
	dbClient, err := s.getConfigDBClient()
	if err != nil {
		return nil, err
	}
	results, err := dbClient.QueryContext(ctx, queryListGrantEditableFields, grantID, s.deploymentID)
	if err != nil {
		return nil, fmt.Errorf("failed to list grant editable fields: %w", err)
	}
	keys := make([]string, 0, len(results))
	for _, row := range results {
		if key, ok := row["field_key"].(string); ok {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// hydrateGrantDetails attaches each grant's exclusion list and editable field list. Grant counts
// per resource are small (admin/audit path, not the visibility hot path), so per-grant follow-up
// queries are acceptable.
func (s *sharingStore) hydrateGrantDetails(ctx context.Context, grants []Grant) ([]Grant, error) {
	for i := range grants {
		excluded, err := s.listExclusions(ctx, grants[i].ID)
		if err != nil {
			return nil, err
		}
		grants[i].ExcludedOUIDs = excluded

		editableFields, err := s.listEditableFields(ctx, grants[i].ID)
		if err != nil {
			return nil, err
		}
		grants[i].EditableFields = editableFields
	}
	return grants, nil
}

// dedupeStrings returns values with duplicates removed, preserving first-seen order.
func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		result = append(result, v)
	}
	return result
}

// nullableStringField extracts a nullable string column value, returning "" for SQL NULL.
func nullableStringField(v interface{}) string {
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

// parseBool parses a boolean-ish DB column value, handling both the Postgres driver's native
// bool and the SQLite driver's int64 (0/1) representation.
func parseBool(value interface{}, fieldName string) (bool, error) {
	switch v := value.(type) {
	case nil:
		return false, fmt.Errorf("required boolean field '%s' is nil", fieldName)
	case bool:
		return v, nil
	case int64:
		return v != 0, nil
	case float64:
		return v != 0, nil
	case string:
		return strings.EqualFold(v, "true") || v == "1", nil
	default:
		return false, fmt.Errorf("failed to parse %s as bool", fieldName)
	}
}
