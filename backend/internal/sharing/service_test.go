// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package sharing

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/system/security"
	"github.com/thunder-id/thunderid/tests/mocks/oumock"
)

const testResourceType ResourceType = "role"
const testOwningOU = "owner-ou"

// testChildOU is a direct child organization unit, the usual children-targeting target.
const testChildOU = "child1"

var errBoom = errors.New("boom")

func TestMain(m *testing.M) {
	security.InitSystemPermissions("")
	os.Exit(m.Run())
}

// requireOwnershipContext returns a context carrying ouID as the caller's own OU claim, with
// permissions set to []string{"system"} when asRoot is true (unrestricted, exempt from the
// ownership check regardless of ouID) or nil otherwise.
func requireOwnershipContext(ouID string, asRoot bool) context.Context {
	var permissions []string
	if asRoot {
		permissions = []string{"system"}
	}
	authCtx := security.NewSecurityContextForTest("test-subject", ouID, "test-token", permissions, nil)
	return security.WithSecurityContextTest(context.Background(), authCtx)
}

// fakeOUHierarchyResolver is a hand-rolled sysauthz.OUHierarchyResolver test double keyed on a
// map of OU ID -> ancestor chain (immediate parent first, root last). An OU absent from the map
// is treated as a root (empty ancestor chain).
type fakeOUHierarchyResolver struct {
	ancestors map[string][]string
}

func (f *fakeOUHierarchyResolver) IsAncestor(
	_ context.Context, ancestorOUID, descendantOUID string,
) (bool, *tidcommon.ServiceError) {
	for _, id := range f.ancestors[descendantOUID] {
		if id == ancestorOUID {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeOUHierarchyResolver) GetAncestorOUIDs(
	_ context.Context, ouID string,
) ([]string, *tidcommon.ServiceError) {
	return f.ancestors[ouID], nil
}

// erroringResolver always fails ancestor-chain lookups, for testing error propagation.
type erroringResolver struct{}

func (r *erroringResolver) IsAncestor(_ context.Context, _, _ string) (bool, *tidcommon.ServiceError) {
	return false, &tidcommon.InternalServerError
}

func (r *erroringResolver) GetAncestorOUIDs(_ context.Context, _ string) ([]string, *tidcommon.ServiceError) {
	return nil, &tidcommon.InternalServerError
}

// fakeTransactioner runs the given function directly without any real transaction semantics.
type fakeTransactioner struct{}

func (f *fakeTransactioner) Transact(ctx context.Context, txFunc func(context.Context) error) error {
	return txFunc(ctx)
}

// fakeDeclaration is a minimal sharing.ResourceTypeDeclaration test double.
type fakeDeclaration struct {
	resourceType ResourceType
	fields       []TemplatedFieldDeclaration
}

func (d *fakeDeclaration) ResourceType() ResourceType                   { return d.resourceType }
func (d *fakeDeclaration) TemplatedFields() []TemplatedFieldDeclaration { return d.fields }

// fakeDeclarationWithDeletionError is a fakeDeclaration that also implements the optional
// DeletionOwnershipError capability, for testing that RequireOwnershipForDeletion prefers it over
// the generic ErrorCoreConfigOwnerOnly.
type fakeDeclarationWithDeletionError struct {
	fakeDeclaration
	err *tidcommon.ServiceError
}

func (d *fakeDeclarationWithDeletionError) ErrorResourceDeletionRestrictedToOwner() *tidcommon.ServiceError {
	return d.err
}

// ServiceTestSuite tests the sharing service implementation.
type ServiceTestSuite struct {
	suite.Suite
	mockStore     *sharingStoreInterfaceMock
	mockOUService *oumock.OrganizationUnitServiceInterfaceMock
	resolver      *fakeOUHierarchyResolver
	svc           *service
}

func TestServiceTestSuite(t *testing.T) {
	suite.Run(t, new(ServiceTestSuite))
}

func (suite *ServiceTestSuite) SetupTest() {
	suite.mockStore = newSharingStoreInterfaceMock(suite.T())
	suite.mockOUService = oumock.NewOrganizationUnitServiceInterfaceMock(suite.T())
	suite.resolver = &fakeOUHierarchyResolver{ancestors: map[string][]string{}}
	suite.svc = newService(
		suite.mockStore, nil, suite.resolver, suite.mockOUService, &fakeTransactioner{}, nil, nil, nil, false,
	).(*service)
}

// --- Registry / editability resolution ---

func (suite *ServiceTestSuite) TestResolveEditability_OwnerAlwaysEditable() {
	suite.svc.RegisterResourceType(&fakeDeclaration{
		resourceType: testResourceType,
		fields:       []TemplatedFieldDeclaration{{Key: "assignments"}},
	})

	editable, svcErr := suite.svc.ResolveEditability(
		context.Background(), testResourceType, "role1", "owner1", "owner1", "assignments")

	suite.Nil(svcErr)
	suite.True(editable, "the owning OU always fully controls its own resource")
	// The owner shortcut must not even need a grant lookup.
	suite.mockStore.AssertNotCalled(suite.T(), "ListGrantsForResource", mock.Anything, mock.Anything, mock.Anything)
}

func (suite *ServiceTestSuite) TestResolveEditability_NotSharedIsNotEditable() {
	suite.svc.RegisterResourceType(&fakeDeclaration{
		resourceType: testResourceType,
		fields:       []TemplatedFieldDeclaration{{Key: "assignments"}},
	})
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{}, nil)

	editable, svcErr := suite.svc.ResolveEditability(
		context.Background(), testResourceType, "role1", "owner1", "ou1", "assignments")

	suite.Nil(svcErr)
	suite.False(editable, "a field can never be editable by an OU the resource isn't even shared to")
}

func (suite *ServiceTestSuite) TestResolveEditability_EditableWhenInGrant() {
	suite.svc.RegisterResourceType(&fakeDeclaration{
		resourceType: testResourceType,
		fields:       []TemplatedFieldDeclaration{{Key: "assignments"}},
	})
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{{OwningOUID: "owner1", Stage: StageShare, TargetScope: TargetScopeAllRoots,
			EditableFields: []string{"assignments"}}}, nil)

	// "ou1" has no ancestors => it is itself a root, reachable by the all_roots grant.
	editable, svcErr := suite.svc.ResolveEditability(
		context.Background(), testResourceType, "role1", "owner1", "ou1", "assignments")

	suite.Nil(svcErr)
	suite.True(editable)
}

func (suite *ServiceTestSuite) TestResolveEditability_NotEditableWhenNotInGrant() {
	suite.svc.RegisterResourceType(&fakeDeclaration{
		resourceType: testResourceType,
		fields:       []TemplatedFieldDeclaration{{Key: "assignments.user"}},
	})
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{{OwningOUID: "owner1", Stage: StageShare, TargetScope: TargetScopeAllRoots,
			EditableFields: []string{"assignments.group"}}}, nil)

	editable, svcErr := suite.svc.ResolveEditability(
		context.Background(), testResourceType, "role1", "owner1", "ou1", "assignments.user")

	suite.Nil(svcErr)
	suite.False(editable)
}

func (suite *ServiceTestSuite) TestResolveEditability_FallsBackToBlanketFieldInGrant() {
	suite.svc.RegisterResourceType(&fakeDeclaration{
		resourceType: testResourceType,
		fields: []TemplatedFieldDeclaration{
			{Key: "assignments"},
			{Key: "assignments.group", FallbackKey: "assignments"},
		},
	})
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{{OwningOUID: "owner1", Stage: StageShare, TargetScope: TargetScopeAllRoots,
			EditableFields: []string{"assignments"}}}, nil)

	editable, svcErr := suite.svc.ResolveEditability(
		context.Background(), testResourceType, "role1", "owner1", "ou1", "assignments.group")

	suite.Nil(svcErr)
	suite.True(editable, "should fall back to the blanket field's membership in the grant")
}

func (suite *ServiceTestSuite) TestResolveEditability_UnregisteredFieldFails() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})

	_, svcErr := suite.svc.ResolveEditability(
		context.Background(), testResourceType, "role1", "owner1", "ou1", "unknown")

	suite.NotNil(svcErr)
	suite.Equal(ErrorFieldNotTemplated.Code, svcErr.Code)
	// An unregistered field fails fast, without ever consulting the store.
	suite.mockStore.AssertNotCalled(suite.T(), "ListGrantsForResource", mock.Anything, mock.Anything, mock.Anything)
}

func (suite *ServiceTestSuite) TestResolveEditableFields_Owner_ReturnsEveryDeclaredField() {
	suite.svc.RegisterResourceType(&fakeDeclaration{
		resourceType: testResourceType,
		fields: []TemplatedFieldDeclaration{
			{Key: "assignments"},
			{Key: "assignments.group", FallbackKey: "assignments"},
		},
	})

	fields, svcErr := suite.svc.ResolveEditableFields(
		context.Background(), testResourceType, "role1", "owner1", "owner1")

	suite.Nil(svcErr)
	suite.ElementsMatch([]string{"assignments", "assignments.group"}, fields)
}

func (suite *ServiceTestSuite) TestResolveEditableFields_NotShared_ReturnsEmpty() {
	suite.svc.RegisterResourceType(&fakeDeclaration{
		resourceType: testResourceType,
		fields:       []TemplatedFieldDeclaration{{Key: "assignments"}},
	})
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{}, nil)

	fields, svcErr := suite.svc.ResolveEditableFields(
		context.Background(), testResourceType, "role1", "owner1", "ou1")

	suite.Nil(svcErr)
	suite.Empty(fields)
}

func (suite *ServiceTestSuite) TestResolveEditableFields_Sharee_ReturnsOnlyGrantMembers() {
	suite.svc.RegisterResourceType(&fakeDeclaration{
		resourceType: testResourceType,
		fields: []TemplatedFieldDeclaration{
			{Key: "assignments.user"},
			{Key: "assignments.group"},
		},
	})
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{{OwningOUID: "owner1", Stage: StageShare, TargetScope: TargetScopeAllRoots,
			EditableFields: []string{"assignments.group"}}}, nil)

	fields, svcErr := suite.svc.ResolveEditableFields(
		context.Background(), testResourceType, "role1", "owner1", "ou1")

	suite.Nil(svcErr)
	suite.Equal([]string{"assignments.group"}, fields)
}

func (suite *ServiceTestSuite) TestListGrants() {
	expected := []Grant{{ID: "grant1", ResourceType: testResourceType, ResourceID: "role1"}}
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return(expected, nil)

	grants, svcErr := suite.svc.ListGrants(context.Background(), testResourceType, "role1")

	suite.Nil(svcErr)
	suite.Equal(expected, grants)
}

func (suite *ServiceTestSuite) TestListGrants_StoreError() {
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return(nil, errBoom)

	_, svcErr := suite.svc.ListGrants(context.Background(), testResourceType, "role1")

	suite.NotNil(svcErr)
}

func (suite *ServiceTestSuite) TestListGrantsPage() {
	expected := []Grant{{ID: "grant3", ResourceType: testResourceType, ResourceID: "role1"}}
	suite.mockStore.On("CountGrantsForResource", mock.Anything, testResourceType, "role1").Return(5, nil)
	suite.mockStore.On("ListGrantsForResourcePage", mock.Anything, testResourceType, "role1", 2, 2).
		Return(expected, nil)

	page, svcErr := suite.svc.ListGrantsPage(context.Background(), testResourceType, "role1", 2, 2)

	suite.Nil(svcErr)
	suite.Equal(expected, page.Grants)
	suite.Equal(5, page.TotalResults)
}

// TestListGrantsPage_OffsetPastEnd proves an offset beyond the last grant still reports the
// real total (so links stay correct) without spending a page query that cannot return rows.
func (suite *ServiceTestSuite) TestListGrantsPage_OffsetPastEnd() {
	suite.mockStore.On("CountGrantsForResource", mock.Anything, testResourceType, "role1").Return(3, nil)

	page, svcErr := suite.svc.ListGrantsPage(context.Background(), testResourceType, "role1", 10, 3)

	suite.Nil(svcErr)
	suite.Empty(page.Grants)
	suite.NotNil(page.Grants, "an empty page must serialize as [] rather than null")
	suite.Equal(3, page.TotalResults)
	suite.mockStore.AssertNotCalled(suite.T(), "ListGrantsForResourcePage",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func (suite *ServiceTestSuite) TestListGrantsPage_CountError() {
	suite.mockStore.On("CountGrantsForResource", mock.Anything, testResourceType, "role1").Return(0, errBoom)

	_, svcErr := suite.svc.ListGrantsPage(context.Background(), testResourceType, "role1", 10, 0)

	suite.NotNil(svcErr)
}

func (suite *ServiceTestSuite) TestListGrantsPage_PageError() {
	suite.mockStore.On("CountGrantsForResource", mock.Anything, testResourceType, "role1").Return(2, nil)
	suite.mockStore.On("ListGrantsForResourcePage", mock.Anything, testResourceType, "role1", 10, 0).
		Return(nil, errBoom)

	_, svcErr := suite.svc.ListGrantsPage(context.Background(), testResourceType, "role1", 10, 0)

	suite.NotNil(svcErr)
}

// TestExportGrants_UsesUnboundedList pins the invariant that makes paging safe to add: export
// reasons over the whole grant graph (it topologically orders by parent/child lineage), so it must
// keep reading the unbounded list. Routing it through the paged query would silently truncate.
func (suite *ServiceTestSuite) TestExportGrants_UsesUnboundedList() {
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{
			{ID: "g1", ResourceType: testResourceType, ResourceID: "role1", OwningOUID: "owner1",
				Stage: StageShare, TargetScope: TargetScopeAllRoots},
		}, nil)

	_, svcErr := suite.svc.ExportGrants(context.Background(), testResourceType, "role1")

	suite.Nil(svcErr)
	suite.mockStore.AssertNotCalled(suite.T(), "ListGrantsForResourcePage",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	suite.mockStore.AssertNotCalled(suite.T(), "CountGrantsForResource",
		mock.Anything, mock.Anything, mock.Anything)
}

func (suite *ServiceTestSuite) TestShare_MissingResourceID() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})

	_, svcErr := suite.svc.Share(
		context.Background(), testResourceType, "", "ou1", "ou1", SharePolicy{AllRoots: true})

	suite.NotNil(svcErr)
	suite.Equal(ErrorInvalidRequestFormat.Code, svcErr.Code)
}

func (suite *ServiceTestSuite) TestShare_MissingOUIDs() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})

	_, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", testOwningOU, "",
		SharePolicy{AllChildren: true})
	suite.NotNil(svcErr)
	suite.Equal(ErrorInvalidRequestFormat.Code, svcErr.Code)

	_, svcErr = suite.svc.Share(context.Background(), testResourceType, "role1", "", "root1",
		SharePolicy{AllChildren: true})
	suite.NotNil(svcErr)
	suite.Equal(ErrorInvalidRequestFormat.Code, svcErr.Code)
}

// TestShare_NoModeSelected_RejectsBeforeAnyStoreAccess proves the owner-self case (no grant lookup
// needed at all, since the owner is always trivially visible to its own resource) still rejects an
// empty policy before ever touching the store: mode detection runs before mode dispatch.
func (suite *ServiceTestSuite) TestShare_NoModeSelected_RejectsBeforeAnyStoreAccess() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})

	_, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", testOwningOU, testOwningOU,
		SharePolicy{})

	suite.NotNil(svcErr)
	suite.Equal(ErrorInvalidRequestFormat.Code, svcErr.Code)
}

// TestShare_BothModesSelected_Rejected proves that populating both root-targeting and
// children-targeting fields in the same call is rejected rather than silently preferring one.
func (suite *ServiceTestSuite) TestShare_BothModesSelected_Rejected() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})

	_, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", testOwningOU, testOwningOU,
		SharePolicy{AllRoots: true, AllChildren: true})

	suite.NotNil(svcErr)
	suite.Equal(ErrorInvalidRequestFormat.Code, svcErr.Code)
}

// TestShare_RootMode_RejectsNonOwnerActingOU proves a sharee (actingOUID != owningOUID) has no
// standing to use root-targeting mode, and that this is rejected before any store access.
func (suite *ServiceTestSuite) TestShare_RootMode_RejectsNonOwnerActingOU() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})

	_, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", testOwningOU, "sharee-ou",
		SharePolicy{AllRoots: true})

	suite.NotNil(svcErr)
	suite.Equal(ErrorInvalidTargetOU.Code, svcErr.Code)
}

// --- Root-targeting mode ---

func (suite *ServiceTestSuite) TestShare_UnregisteredResourceType() {
	_, svcErr := suite.svc.Share(
		context.Background(), testResourceType, "role1", "ou1", "ou1", SharePolicy{AllRoots: true})

	suite.NotNil(svcErr)
	suite.Equal(ErrorResourceTypeNotRegistered.Code, svcErr.Code)
}

func (suite *ServiceTestSuite) TestShare_AllRoots() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	suite.mockStore.On("CreateGrant", mock.Anything, mock.MatchedBy(func(g Grant) bool {
		return g.ResourceType == testResourceType && g.ResourceID == "role1" && g.OwningOUID == "ou1" &&
			g.Stage == StageShare && g.TargetScope == TargetScopeAllRoots && g.TargetOUID == ""
	})).Return(nil)

	grants, svcErr := suite.svc.Share(
		context.Background(), testResourceType, "role1", "ou1", "ou1", SharePolicy{AllRoots: true})

	suite.Nil(svcErr)
	suite.Len(grants, 1)
}

func (suite *ServiceTestSuite) TestShare_SelectedRoots_RejectsNonRootTarget() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	// "child1" has a parent, so it is not a root.
	suite.resolver.ancestors["child1"] = []string{"root1"}

	_, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", "ou1", "ou1", SharePolicy{
		RootOUIDs: []string{"child1"},
	})

	suite.NotNil(svcErr)
	suite.Equal(ErrorInvalidTargetOU.Code, svcErr.Code)
}

func (suite *ServiceTestSuite) TestShare_SelectedRoots_Success() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	// "root1" has no entry in the ancestors map => treated as a root.
	suite.mockStore.On("CreateGrant", mock.Anything, mock.MatchedBy(func(g Grant) bool {
		return g.TargetScope == TargetScopeRoot && g.TargetOUID == "root1"
	})).Return(nil)

	grants, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", "ou1", "ou1", SharePolicy{
		RootOUIDs: []string{"root1"},
	})

	suite.Nil(svcErr)
	suite.Len(grants, 1)
}

func (suite *ServiceTestSuite) TestShare_AllRoots_WithExclusions_Success() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	// Both exclusions have no entry in the ancestors map => treated as roots.
	suite.mockStore.On("CreateGrant", mock.Anything, mock.MatchedBy(func(g Grant) bool {
		return g.TargetScope == TargetScopeAllRoots &&
			slices.Equal(g.ExcludedOUIDs, []string{"excludedRoot1", "excludedRoot2"})
	})).Return(nil)

	grants, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", "ou1", "ou1", SharePolicy{
		AllRoots:          true,
		ExcludedRootOUIDs: []string{"excludedRoot1", "excludedRoot2"},
	})

	suite.Nil(svcErr)
	suite.Len(grants, 1)
}

func (suite *ServiceTestSuite) TestShare_AllRoots_RejectsNonRootExclusion() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	// "child1" has a parent, so it is not a root and cannot be excluded from an all-roots share.
	suite.resolver.ancestors["child1"] = []string{"root1"}

	_, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", "ou1", "ou1", SharePolicy{
		AllRoots:          true,
		ExcludedRootOUIDs: []string{"child1"},
	})

	suite.NotNil(svcErr)
	suite.Equal(ErrorInvalidTargetOU.Code, svcErr.Code)
}

// --- Cross-tree share restriction ---

// TestShare_SelectedRoots_NonRootOwner_OwnRoot_AlwaysAllowed proves a non-root owner may always
// push a share up to its own tree's root, with no config involved — this is the standard first
// step of the push-to-own-root-then-reshare pattern and is never restricted.
func (suite *ServiceTestSuite) TestShare_SelectedRoots_NonRootOwner_OwnRoot_AlwaysAllowed() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	// "ou1" is a non-root child of "ownRoot" (its own tree's root).
	suite.resolver.ancestors["ou1"] = []string{"ownRoot"}
	suite.mockStore.On("CreateGrant", mock.Anything, mock.MatchedBy(func(g Grant) bool {
		return g.TargetScope == TargetScopeRoot && g.TargetOUID == "ownRoot"
	})).Return(nil)

	grants, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", "ou1", "ou1", SharePolicy{
		RootOUIDs: []string{"ownRoot"},
	})

	suite.Nil(svcErr)
	suite.Len(grants, 1)
}

// TestShare_SelectedRoots_NonRootOwner_ForeignRoot_RestrictedByDefault proves a non-root owner
// cannot reach a foreign tree's root when no reader is installed (the deny-by-default posture).
func (suite *ServiceTestSuite) TestShare_SelectedRoots_NonRootOwner_ForeignRoot_RestrictedByDefault() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	// "ou1"'s own root is "root1"; "root2" belongs to a different tree entirely.
	suite.resolver.ancestors["ou1"] = []string{"root1"}

	_, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", "ou1", "ou1", SharePolicy{
		RootOUIDs: []string{"root2"},
	})

	suite.NotNil(svcErr)
	suite.Equal(ErrorCrossTreeShareRestricted.Code, svcErr.Code)
	suite.mockStore.AssertNotCalled(suite.T(), "CreateGrant", mock.Anything, mock.Anything)
}

// TestShare_SelectedRoots_NonRootOwner_ForeignRoot_AllowedWhenConfigEnabled proves the
// allow_child_ou_cross_tree_sharing deployment setting lifts the restriction.
func (suite *ServiceTestSuite) TestShare_SelectedRoots_NonRootOwner_ForeignRoot_AllowedWhenConfigEnabled() {
	suite.svc = newService(suite.mockStore, nil, suite.resolver, suite.mockOUService, &fakeTransactioner{},
		nil, nil, nil, true).(*service)
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	suite.resolver.ancestors["ou1"] = []string{"root1"}
	suite.mockStore.On("CreateGrant", mock.Anything, mock.MatchedBy(func(g Grant) bool {
		return g.TargetScope == TargetScopeRoot && g.TargetOUID == "root2"
	})).Return(nil)

	grants, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", "ou1", "ou1", SharePolicy{
		RootOUIDs: []string{"root2"},
	})

	suite.Nil(svcErr)
	suite.Len(grants, 1)
}

// TestShare_RootOwner_ForeignRoot_NeverRestricted proves a root owner's Root-to-Root sharing is
// exempt from the cross-tree check entirely, regardless of config — this restriction is about a
// child reaching outside its own tree, not about root-to-root distribution.
func (suite *ServiceTestSuite) TestShare_RootOwner_ForeignRoot_NeverRestricted() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	// "ou1" has no entry in the ancestors map => it is itself a root.
	suite.mockStore.On("CreateGrant", mock.Anything, mock.MatchedBy(func(g Grant) bool {
		return g.TargetScope == TargetScopeRoot && g.TargetOUID == "root2"
	})).Return(nil)

	grants, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", "ou1", "ou1", SharePolicy{
		RootOUIDs: []string{"root2"},
	})

	suite.Nil(svcErr)
	suite.Len(grants, 1)
}

// TestShare_AllRoots_NonRootOwner_RestrictedByDefault proves AllRoots is rejected outright for a
// non-root owner when cross-tree sharing isn't enabled, since it inherently reaches every tree.
func (suite *ServiceTestSuite) TestShare_AllRoots_NonRootOwner_RestrictedByDefault() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	suite.resolver.ancestors["ou1"] = []string{"root1"}

	_, svcErr := suite.svc.Share(
		context.Background(), testResourceType, "role1", "ou1", "ou1", SharePolicy{AllRoots: true})

	suite.NotNil(svcErr)
	suite.Equal(ErrorCrossTreeShareRestricted.Code, svcErr.Code)
	suite.mockStore.AssertNotCalled(suite.T(), "CreateGrant", mock.Anything, mock.Anything)
}

// TestShare_AllRoots_NonRootOwner_AllowedWhenConfigEnabled mirrors the RootOUIDs case for AllRoots.
func (suite *ServiceTestSuite) TestShare_AllRoots_NonRootOwner_AllowedWhenConfigEnabled() {
	suite.svc = newService(suite.mockStore, nil, suite.resolver, suite.mockOUService, &fakeTransactioner{},
		nil, nil, nil, true).(*service)
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	suite.resolver.ancestors["ou1"] = []string{"root1"}
	suite.mockStore.On("CreateGrant", mock.Anything, mock.MatchedBy(func(g Grant) bool {
		return g.TargetScope == TargetScopeAllRoots
	})).Return(nil)

	grants, svcErr := suite.svc.Share(
		context.Background(), testResourceType, "role1", "ou1", "ou1", SharePolicy{AllRoots: true})

	suite.Nil(svcErr)
	suite.Len(grants, 1)
}

// --- ExportGrants ---

func (suite *ServiceTestSuite) TestExportGrants_NoGrants_ReturnsEmpty() {
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{}, nil)

	replayable, svcErr := suite.svc.ExportGrants(context.Background(), testResourceType, "role1")

	suite.Nil(svcErr)
	suite.Empty(replayable)
}

func (suite *ServiceTestSuite) TestExportGrants_StoreError_Propagates() {
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return(nil, errBoom)

	_, svcErr := suite.svc.ExportGrants(context.Background(), testResourceType, "role1")

	suite.NotNil(svcErr)
}

// TestExportGrants_OwnerRootShare proves a root-targeting share (owner -> a specific Root) is
// exported with ActingOUID == the owner and a matching RootOUIDs policy.
func (suite *ServiceTestSuite) TestExportGrants_OwnerRootShare() {
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{
			{
				ID: "g1", OwningOUID: testOwningOU, Stage: StageShare,
				TargetScope: TargetScopeRoot, TargetOUID: "root1",
				EditableFields: []string{"assignments.group"},
			},
		}, nil)

	replayable, svcErr := suite.svc.ExportGrants(context.Background(), testResourceType, "role1")

	suite.Nil(svcErr)
	suite.Require().Len(replayable, 1)
	suite.Equal(testOwningOU, replayable[0].ActingOUID)
	want := SharePolicy{RootOUIDs: []string{"root1"}, EditableFields: []string{"assignments.group"}}
	suite.Equal(want, replayable[0].Policy)
}

// TestExportGrants_AllRootsWithExclusions proves an AllRoots share round-trips its exclusion list.
func (suite *ServiceTestSuite) TestExportGrants_AllRootsWithExclusions() {
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{
			{
				ID: "g1", OwningOUID: testOwningOU, Stage: StageShare,
				TargetScope: TargetScopeAllRoots, ExcludedOUIDs: []string{"exA"},
			},
		}, nil)

	replayable, svcErr := suite.svc.ExportGrants(context.Background(), testResourceType, "role1")

	suite.Nil(svcErr)
	suite.Require().Len(replayable, 1)
	suite.Equal(testOwningOU, replayable[0].ActingOUID)
	suite.Equal(SharePolicy{AllRoots: true, ExcludedRootOUIDs: []string{"exA"}}, replayable[0].Policy)
}

// TestExportGrants_OwnerAllChildren proves an owner distributing directly to its own subtree
// (Stage: share) is exported with ActingOUID == the owner, not derived from TargetOUID: Stage
// takes priority over TargetScope when deriving ActingOUID.
func (suite *ServiceTestSuite) TestExportGrants_OwnerAllChildren() {
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{
			{
				ID: "g1", OwningOUID: testOwningOU, Stage: StageShare,
				TargetScope: TargetScopeAllChildren, TargetOUID: testOwningOU,
			},
		}, nil)

	replayable, svcErr := suite.svc.ExportGrants(context.Background(), testResourceType, "role1")

	suite.Nil(svcErr)
	suite.Require().Len(replayable, 1)
	suite.Equal(testOwningOU, replayable[0].ActingOUID)
	suite.Equal(SharePolicy{AllChildren: true}, replayable[0].Policy)
}

// TestExportGrants_ReshareAllChildren proves a sharee's all_children reshare is exported with
// ActingOUID derived directly from TargetOUID (the anchor), no ancestor lookup needed.
func (suite *ServiceTestSuite) TestExportGrants_ReshareAllChildren() {
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{
			{
				ID: "g1", OwningOUID: testOwningOU, Stage: StageReshare,
				TargetScope: TargetScopeAllChildren, TargetOUID: "sharee-ou",
				ExcludedOUIDs: []string{"excluded-child"},
			},
		}, nil)

	replayable, svcErr := suite.svc.ExportGrants(context.Background(), testResourceType, "role1")

	suite.Nil(svcErr)
	suite.Require().Len(replayable, 1)
	suite.Equal("sharee-ou", replayable[0].ActingOUID)
	suite.Equal(SharePolicy{AllChildren: true, ExcludedOUIDs: []string{"excluded-child"}}, replayable[0].Policy)
}

// TestExportGrants_ReshareExplicitOU proves an explicit-OU reshare's ActingOUID is derived via one
// ancestor lookup on TargetOUID (its issuer must be its immediate parent).
func (suite *ServiceTestSuite) TestExportGrants_ReshareExplicitOU() {
	suite.resolver.ancestors["child1"] = []string{"parent-ou", "root1"}
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{
			{
				ID: "g1", OwningOUID: testOwningOU, Stage: StageReshare,
				TargetScope: TargetScopeOU, TargetOUID: "child1",
				EditableFields: []string{"assignments.user"},
			},
		}, nil)

	replayable, svcErr := suite.svc.ExportGrants(context.Background(), testResourceType, "role1")

	suite.Nil(svcErr)
	suite.Require().Len(replayable, 1)
	suite.Equal("parent-ou", replayable[0].ActingOUID)
	want := SharePolicy{OUIDs: []string{"child1"}, EditableFields: []string{"assignments.user"}}
	suite.Equal(want, replayable[0].Policy)
}

// TestExportGrants_ReshareExplicitOU_AncestorLookupError_Propagates proves an ancestor-resolution
// failure surfaces as an error rather than a wrong or silently-omitted ActingOUID.
func (suite *ServiceTestSuite) TestExportGrants_ReshareExplicitOU_AncestorLookupError_Propagates() {
	suite.svc.ouHierarchyResolver = &erroringResolver{}
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{
			{ID: "g1", Stage: StageReshare, TargetScope: TargetScopeOU, TargetOUID: "child1"},
		}, nil)

	_, svcErr := suite.svc.ExportGrants(context.Background(), testResourceType, "role1")

	suite.NotNil(svcErr)
}

// TestExportGrants_MultiHopChain_OrderedCorrectly proves a three-hop reshare chain is exported in
// an order safe to replay via Share(): each grant appears only after the one it names as its
// ParentGrantID, regardless of the order the store happens to return them in.
func (suite *ServiceTestSuite) TestExportGrants_MultiHopChain_OrderedCorrectly() {
	suite.resolver.ancestors["grandchild"] = []string{"child1", "root1"}
	// Deliberately returned out of dependency order (deepest first) to prove the sort, not the
	// store's own ordering, is what determines the result.
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{
			{
				ID: "grant-grandchild", Stage: StageReshare, TargetScope: TargetScopeOU,
				TargetOUID: "grandchild", ParentGrantID: "grant-child",
			},
			{
				ID: "grant-root", OwningOUID: testOwningOU, Stage: StageShare,
				TargetScope: TargetScopeRoot, TargetOUID: "root1",
			},
			{
				ID: "grant-child", Stage: StageReshare, TargetScope: TargetScopeAllChildren,
				TargetOUID: "root1", ParentGrantID: "grant-root",
			},
		}, nil)

	replayable, svcErr := suite.svc.ExportGrants(context.Background(), testResourceType, "role1")

	suite.Nil(svcErr)
	suite.Require().Len(replayable, 3)
	suite.Equal(testOwningOU, replayable[0].ActingOUID, "the root share has no parent, so it must come first")
	suite.Equal("root1", replayable[1].ActingOUID, "the all_children reshare's parent is the root share")
	suite.Equal("child1", replayable[2].ActingOUID, "the explicit reshare's parent is the all_children reshare")
}

// TestExportGrants_OrphanParent_ReturnsInternalError proves a ParentGrantID pointing outside the
// resource's own grant set (which should never happen) is refused rather than silently dropped or
// left permanently unordered.
func (suite *ServiceTestSuite) TestExportGrants_OrphanParent_ReturnsInternalError() {
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{
			{ID: "g1", Stage: StageReshare, TargetScope: TargetScopeOU, TargetOUID: "x", ParentGrantID: "missing"},
		}, nil)

	_, svcErr := suite.svc.ExportGrants(context.Background(), testResourceType, "role1")

	suite.NotNil(svcErr)
}

// --- Children-targeting mode ---

// TestShare_ChildrenMode_OwnerSelf_IsShareNotReshare is the Stage bug regression test: an owner
// distributing directly into its own subtree is a first-hop grant (StageShare), not a reshare,
// even though it uses children-targeting mode.
func (suite *ServiceTestSuite) TestShare_ChildrenMode_OwnerSelf_IsShareNotReshare() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	// No ListGrantsForResource stub at all: the owner-self case must skip that lookup entirely,
	// since the owner is always trivially visible to its own resource.
	suite.mockStore.On("CreateGrant", mock.Anything, mock.MatchedBy(func(g Grant) bool {
		return g.Stage == StageShare && g.TargetScope == TargetScopeAllChildren &&
			g.TargetOUID == testOwningOU && g.ParentGrantID == "" && g.OwningOUID == testOwningOU
	})).Return(nil)

	grants, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", testOwningOU, testOwningOU,
		SharePolicy{AllChildren: true})

	suite.Nil(svcErr)
	suite.Len(grants, 1)
	suite.mockStore.AssertNotCalled(suite.T(), "ListGrantsForResource", mock.Anything, mock.Anything, mock.Anything)
}

// TestShare_ChildrenMode_OwnerSelf_SelectedOUs_IsShareNotReshare covers the explicit-OUIDs branch
// of the same Stage bug: the owner naming its own direct children explicitly (not AllChildren) is
// also a first-hop grant.
func (suite *ServiceTestSuite) TestShare_ChildrenMode_OwnerSelf_SelectedOUs_IsShareNotReshare() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	suite.resolver.ancestors["child1"] = []string{testOwningOU}
	suite.mockStore.On("CreateGrant", mock.Anything, mock.MatchedBy(func(g Grant) bool {
		return g.Stage == StageShare && g.TargetScope == TargetScopeOU && g.TargetOUID == "child1" &&
			g.ParentGrantID == "" && g.OwningOUID == testOwningOU
	})).Return(nil)

	grants, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", testOwningOU, testOwningOU,
		SharePolicy{OUIDs: []string{"child1"}})

	suite.Nil(svcErr)
	suite.Len(grants, 1)
	suite.mockStore.AssertNotCalled(suite.T(), "ListGrantsForResource", mock.Anything, mock.Anything, mock.Anything)
}

func (suite *ServiceTestSuite) TestShare_ChildrenMode_FailsWhenActingOUNotVisible() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{}, nil)

	_, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", testOwningOU, "root1",
		SharePolicy{AllChildren: true})

	suite.NotNil(svcErr)
	suite.Equal(ErrorNotShared.Code, svcErr.Code)
}

func (suite *ServiceTestSuite) TestShare_ChildrenMode_AllChildren_AnchorsOnActingOU() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	existingGrant := Grant{
		ID: "grant1", ResourceType: testResourceType, ResourceID: "role1",
		OwningOUID: testOwningOU, Stage: StageShare, TargetScope: TargetScopeAllRoots,
	}
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{existingGrant}, nil)
	suite.mockStore.On("CreateGrant", mock.Anything, mock.MatchedBy(func(g Grant) bool {
		return g.Stage == StageReshare && g.TargetScope == TargetScopeAllChildren &&
			g.TargetOUID == "root1" && g.ParentGrantID == "grant1" && g.OwningOUID == testOwningOU
	})).Return(nil)

	grants, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", testOwningOU, "root1",
		SharePolicy{AllChildren: true})

	suite.Nil(svcErr)
	suite.Len(grants, 1)
}

// TestReshare_ChainedDelegation_IntermediateOUCanResharFurther proves an OU made visible only by
// an earlier explicit reshare (not a root, not the owner) may itself reshare further, and the new
// grant's ParentGrantID links to the grant that gave it its own access (for cascade-unshare).
func (suite *ServiceTestSuite) TestShare_ChildrenMode_ChainedDelegation_IntermediateOUCanShareFurther() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	suite.resolver.ancestors["child1"] = []string{"root1"}
	grant := Grant{ID: "share1", ResourceType: testResourceType, ResourceID: "role1",
		OwningOUID: testOwningOU, Stage: StageShare, TargetScope: TargetScopeRoot, TargetOUID: "root1"}
	reshareToChild := Grant{ID: "reshare1", ResourceType: testResourceType, ResourceID: "role1",
		OwningOUID: testOwningOU, Stage: StageReshare, TargetScope: TargetScopeOU, TargetOUID: "child1",
		ParentGrantID: "share1"}
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{grant, reshareToChild}, nil)
	suite.resolver.ancestors["grandchild1"] = []string{"child1", "root1"}
	suite.mockStore.On("CreateGrant", mock.Anything, mock.MatchedBy(func(g Grant) bool {
		return g.Stage == StageReshare && g.TargetScope == TargetScopeOU && g.TargetOUID == "grandchild1" &&
			g.ParentGrantID == "reshare1" && g.OwningOUID == testOwningOU
	})).Return(nil)

	grants, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", testOwningOU, "child1",
		SharePolicy{OUIDs: []string{"grandchild1"}})

	suite.Nil(svcErr)
	suite.Len(grants, 1)
}

func (suite *ServiceTestSuite) TestShare_ChildrenMode_SelectedOUs_RejectsGrandchildTarget() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{{Stage: StageShare, TargetScope: TargetScopeAllRoots}}, nil)
	// "grandchild1" is within root1's subtree, but is not root1's *immediate* child.
	suite.resolver.ancestors["child1"] = []string{"root1"}
	suite.resolver.ancestors["grandchild1"] = []string{"child1", "root1"}

	_, svcErr := suite.svc.Share(
		context.Background(), testResourceType, "role1", testOwningOU, "root1", SharePolicy{
			OUIDs: []string{"grandchild1"},
		})

	suite.NotNil(svcErr)
	suite.Equal(ErrorInvalidTargetOU.Code, svcErr.Code)
}

func (suite *ServiceTestSuite) TestShare_ChildrenMode_SelectedOUs_RejectsRootTarget() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{{Stage: StageShare, TargetScope: TargetScopeAllRoots}}, nil)
	// "otherRoot" has no parent, so it can never be anyone's immediate child.

	_, svcErr := suite.svc.Share(
		context.Background(), testResourceType, "role1", testOwningOU, "root1", SharePolicy{
			OUIDs: []string{"otherRoot"},
		})

	suite.NotNil(svcErr)
	suite.Equal(ErrorInvalidTargetOU.Code, svcErr.Code)
}

func (suite *ServiceTestSuite) TestShare_ChildrenMode_SelectedOUs_Success() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{{ID: "grant1", Stage: StageShare, TargetScope: TargetScopeAllRoots}}, nil)
	suite.resolver.ancestors["child1"] = []string{"root1"}
	suite.mockStore.On("CreateGrant", mock.Anything, mock.MatchedBy(func(g Grant) bool {
		return g.Stage == StageReshare && g.TargetScope == TargetScopeOU && g.TargetOUID == "child1"
	})).Return(nil)

	grants, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", testOwningOU, "root1",
		SharePolicy{
			OUIDs: []string{"child1"},
		})

	suite.Nil(svcErr)
	suite.Len(grants, 1)
}

func (suite *ServiceTestSuite) TestShare_ChildrenMode_AllChildren_WithExclusions_Success() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{{ID: "grant1", Stage: StageShare, TargetScope: TargetScopeAllRoots}}, nil)
	suite.resolver.ancestors["excludedChild"] = []string{"root1"}
	suite.mockStore.On("CreateGrant", mock.Anything, mock.MatchedBy(func(g Grant) bool {
		return g.Stage == StageReshare && g.TargetScope == TargetScopeAllChildren &&
			slices.Equal(g.ExcludedOUIDs, []string{"excludedChild"})
	})).Return(nil)

	grants, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", testOwningOU, "root1",
		SharePolicy{
			AllChildren:   true,
			ExcludedOUIDs: []string{"excludedChild"},
		})

	suite.Nil(svcErr)
	suite.Len(grants, 1)
}

func (suite *ServiceTestSuite) TestShare_ChildrenMode_AllChildren_RejectsExclusionOutsideSubtree() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{{Stage: StageShare, TargetScope: TargetScopeAllRoots}}, nil)
	// "unrelatedOU" is a descendant of a different root, not "root1".
	suite.resolver.ancestors["unrelatedOU"] = []string{"otherRoot"}

	_, svcErr := suite.svc.Share(
		context.Background(), testResourceType, "role1", testOwningOU, "root1", SharePolicy{
			AllChildren:   true,
			ExcludedOUIDs: []string{"unrelatedOU"},
		})

	suite.NotNil(svcErr)
	suite.Equal(ErrorInvalidTargetOU.Code, svcErr.Code)
}

// --- Grant-creation-time editable field resolution ---

func (suite *ServiceTestSuite) TestShare_Owner_DefaultEditableFields_IsEveryDeclaredField() {
	suite.svc.RegisterResourceType(&fakeDeclaration{
		resourceType: testResourceType,
		fields: []TemplatedFieldDeclaration{
			{Key: "assignments.user"}, {Key: "assignments.group"},
		},
	})
	suite.mockStore.On("CreateGrant", mock.Anything, mock.MatchedBy(func(g Grant) bool {
		return slices.Contains(g.EditableFields, "assignments.user") &&
			slices.Contains(g.EditableFields, "assignments.group") && len(g.EditableFields) == 2
	})).Return(nil)

	_, svcErr := suite.svc.Share(
		context.Background(), testResourceType, "role1", "ou1", "ou1", SharePolicy{AllRoots: true})

	suite.Nil(svcErr)
}

func (suite *ServiceTestSuite) TestShare_Owner_ExplicitEditableFields_RejectsUndeclaredField() {
	suite.svc.RegisterResourceType(&fakeDeclaration{
		resourceType: testResourceType,
		fields:       []TemplatedFieldDeclaration{{Key: "assignments.user"}},
	})

	_, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", "ou1", "ou1", SharePolicy{
		AllRoots: true, EditableFields: []string{"unknown"},
	})

	suite.NotNil(svcErr)
	suite.Equal(ErrorFieldNotTemplated.Code, svcErr.Code)
}

func (suite *ServiceTestSuite) TestShare_Reshare_DefaultEditableFields_InheritsActingOUsOwnSet() {
	suite.svc.RegisterResourceType(&fakeDeclaration{
		resourceType: testResourceType,
		fields:       []TemplatedFieldDeclaration{{Key: "assignments.user"}, {Key: "assignments.group"}},
	})
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{{OwningOUID: testOwningOU, Stage: StageShare, TargetScope: TargetScopeAllRoots,
			EditableFields: []string{"assignments.user"}}}, nil)
	suite.mockStore.On("CreateGrant", mock.Anything, mock.MatchedBy(func(g Grant) bool {
		return slices.Equal(g.EditableFields, []string{"assignments.user"})
	})).Return(nil)

	// "root1" has no ancestors => it is itself a root, reachable by the all_roots grant above.
	_, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", testOwningOU, "root1",
		SharePolicy{AllChildren: true})

	suite.Nil(svcErr)
}

func (suite *ServiceTestSuite) TestShare_Reshare_ExplicitEditableFields_SubsetOfInheritedIsAllowed() {
	suite.svc.RegisterResourceType(&fakeDeclaration{
		resourceType: testResourceType,
		fields:       []TemplatedFieldDeclaration{{Key: "assignments.user"}, {Key: "assignments.group"}},
	})
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{{OwningOUID: testOwningOU, Stage: StageShare, TargetScope: TargetScopeAllRoots,
			EditableFields: []string{"assignments.user", "assignments.group"}}}, nil)
	suite.mockStore.On("CreateGrant", mock.Anything, mock.MatchedBy(func(g Grant) bool {
		return slices.Equal(g.EditableFields, []string{"assignments.user"})
	})).Return(nil)

	_, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", testOwningOU, "root1",
		SharePolicy{AllChildren: true, EditableFields: []string{"assignments.user"}})

	suite.Nil(svcErr)
}

// TestShare_Reshare_ExplicitEditableFields_RejectsExpansion is the scope-down-only regression
// test: a reshare naming a field the acting OU cannot itself currently edit must be rejected, not
// silently granted.
func (suite *ServiceTestSuite) TestShare_Reshare_ExplicitEditableFields_RejectsExpansion() {
	suite.svc.RegisterResourceType(&fakeDeclaration{
		resourceType: testResourceType,
		fields:       []TemplatedFieldDeclaration{{Key: "assignments.user"}, {Key: "assignments.group"}},
	})
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{{OwningOUID: testOwningOU, Stage: StageShare, TargetScope: TargetScopeAllRoots,
			EditableFields: []string{"assignments.user"}}}, nil)

	_, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1", testOwningOU, "root1",
		SharePolicy{AllChildren: true, EditableFields: []string{"assignments.group"}})

	suite.NotNil(svcErr)
	suite.Equal(ErrorEditabilityCannotBeExpanded.Code, svcErr.Code)
	suite.mockStore.AssertNotCalled(suite.T(), "CreateGrant", mock.Anything, mock.Anything)
}

// TestResolveEditableFields_PrefersDeepestGrantOverBroaderUpstreamOne is the nearestGrant
// deepest-match regression test: when a broad upstream grant (from the owner) and a narrower
// reshare from a closer intermediate OU both cover the same descendant, the descendant's
// editability must reflect the narrower, more specific grant — not the broader upstream one that
// merely also happens to reach that deep.
func (suite *ServiceTestSuite) TestResolveEditableFields_PrefersDeepestGrantOverBroaderUpstreamOne() {
	suite.svc.RegisterResourceType(&fakeDeclaration{
		resourceType: testResourceType,
		fields:       []TemplatedFieldDeclaration{{Key: "assignments.user"}, {Key: "assignments.group"}},
	})
	suite.resolver.ancestors["x"] = []string{testOwningOU}
	suite.resolver.ancestors["y"] = []string{"x", testOwningOU}

	broadUpstreamGrant := Grant{ID: "broad", OwningOUID: testOwningOU, Stage: StageShare,
		TargetScope: TargetScopeAllChildren, TargetOUID: testOwningOU,
		EditableFields: []string{"assignments.user", "assignments.group"}}
	narrowerReshareFromX := Grant{ID: "narrow", OwningOUID: testOwningOU, Stage: StageReshare,
		TargetScope: TargetScopeAllChildren, TargetOUID: "x", ParentGrantID: "broad",
		EditableFields: []string{"assignments.user"}}
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{broadUpstreamGrant, narrowerReshareFromX}, nil)

	fields, svcErr := suite.svc.ResolveEditableFields(
		context.Background(), testResourceType, "role1", testOwningOU, "y")

	suite.Nil(svcErr)
	suite.Equal([]string{"assignments.user"}, fields,
		"y must inherit x's own narrower grant, not the broader upstream one that also reaches this deep")
}

// TestResolveEditableFields_ExplicitOUReshareBeatsBroaderAllChildrenGrant is a second regression
// test for the same nearestGrant selection bug, this time with the narrower grant shaped as an
// explicit "ou" reshare (not "all_children") from the immediate parent — the shape actually used
// when sharing to specific ouIds rather than allChildren. The AllChildren-vs-AllChildren case above
// does not exercise this: an explicit "ou" grant is resolved in a separate code path from
// "all_children" grants, and that path was still checked strictly after (never before) a
// more-distant ancestor's "all_children" grant, so a broad grandparent-level allChildren grant
// incorrectly won over the immediate parent's own, narrower, explicit reshare.
func (suite *ServiceTestSuite) TestResolveEditableFields_ExplicitOUReshareBeatsBroaderAllChildrenGrant() {
	suite.svc.RegisterResourceType(&fakeDeclaration{
		resourceType: testResourceType,
		fields:       []TemplatedFieldDeclaration{{Key: "assignments.user"}, {Key: "assignments.group"}},
	})
	suite.resolver.ancestors["x"] = []string{testOwningOU}
	suite.resolver.ancestors["y"] = []string{"x", testOwningOU}

	broadUpstreamGrant := Grant{ID: "broad", OwningOUID: testOwningOU, Stage: StageShare,
		TargetScope: TargetScopeAllChildren, TargetOUID: testOwningOU,
		EditableFields: []string{"assignments.user", "assignments.group"}}
	explicitReshareFromXToY := Grant{ID: "narrow", OwningOUID: testOwningOU, Stage: StageReshare,
		TargetScope: TargetScopeOU, TargetOUID: "y", ParentGrantID: "broad",
		EditableFields: []string{"assignments.group"}}
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{broadUpstreamGrant, explicitReshareFromXToY}, nil)

	fields, svcErr := suite.svc.ResolveEditableFields(
		context.Background(), testResourceType, "role1", testOwningOU, "y")

	suite.Nil(svcErr)
	suite.Equal([]string{"assignments.group"}, fields,
		"y must inherit x's own explicit, narrower reshare, not the broader all_children grant "+
			"anchored further up the chain that also happens to reach this deep")
}

// --- Visibility (IsShared / ListSharedResourceIDs) ---

func (suite *ServiceTestSuite) TestIsShared_OwnerAlwaysVisibleEvenWithNoGrants() {
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{{OwningOUID: testOwningOU, Stage: StageReshare, TargetScope: TargetScopeAllChildren,
			TargetOUID: testOwningOU}}, nil)

	visible, svcErr := suite.svc.IsShared(context.Background(), testResourceType, "role1", testOwningOU)

	suite.Nil(svcErr)
	suite.True(visible)
}

func (suite *ServiceTestSuite) TestIsShared_RootVisibleViaAllRoots() {
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{{OwningOUID: testOwningOU, Stage: StageShare, TargetScope: TargetScopeAllRoots}}, nil)

	// "root1" has no ancestors => it is itself the root.
	visible, svcErr := suite.svc.IsShared(context.Background(), testResourceType, "role1", "root1")

	suite.Nil(svcErr)
	suite.True(visible)
}

func (suite *ServiceTestSuite) TestIsShared_ChildVisibleViaReshareAllChildren() {
	suite.resolver.ancestors["child1"] = []string{"root1"}
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{
			{OwningOUID: testOwningOU, Stage: StageShare, TargetScope: TargetScopeRoot, TargetOUID: "root1"},
			{OwningOUID: testOwningOU, Stage: StageReshare, TargetScope: TargetScopeAllChildren, TargetOUID: "root1"},
		}, nil)

	visible, svcErr := suite.svc.IsShared(context.Background(), testResourceType, "role1", "child1")

	suite.Nil(svcErr)
	suite.True(visible)
}

// TestIsShared_BrokenChain_MissingIntermediateHop is the point-4 chain-integrity regression test:
// a grandchild is NOT visible via an explicit grant naming it directly if the hop from its
// immediate parent was never actually granted — access must chain unbroken from the root down.
func (suite *ServiceTestSuite) TestIsShared_BrokenChain_MissingIntermediateHop() {
	suite.resolver.ancestors["child1"] = []string{"root1"}
	suite.resolver.ancestors["grandchild1"] = []string{"child1", "root1"}
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{
			{OwningOUID: testOwningOU, Stage: StageShare, TargetScope: TargetScopeRoot, TargetOUID: "root1"},
			// No grant at all covers "child1" — only a (data-inconsistent, or stale) row naming the
			// grandchild directly. It must not count: the hop from root1 to child1 was never granted.
			{OwningOUID: testOwningOU, Stage: StageReshare, TargetScope: TargetScopeOU, TargetOUID: "grandchild1"},
		}, nil)

	visible, svcErr := suite.svc.IsShared(context.Background(), testResourceType, "role1", "grandchild1")

	suite.Nil(svcErr)
	suite.False(visible, "a grant naming a deeper OU directly must not count when its parent was never granted")
}

// TestIsShared_BrokenChain_ExclusionCutsOffDescendants proves an all_children exclusion at one
// level removes visibility for the excluded OU's entire subtree, even a grandchild reached via a
// separate, otherwise-valid explicit hop below it.
func (suite *ServiceTestSuite) TestIsShared_BrokenChain_ExclusionCutsOffDescendants() {
	suite.resolver.ancestors["excludedChild"] = []string{"root1"}
	suite.resolver.ancestors["grandchildOfExcluded"] = []string{"excludedChild", "root1"}
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{
			{OwningOUID: testOwningOU, Stage: StageShare, TargetScope: TargetScopeRoot, TargetOUID: "root1"},
			{OwningOUID: testOwningOU, Stage: StageReshare, TargetScope: TargetScopeAllChildren,
				TargetOUID: "root1", ExcludedOUIDs: []string{"excludedChild"}},
			// Even though this row explicitly names the grandchild, its parent ("excludedChild") was
			// carved out of the all_children grant, so the grandchild must not be visible either.
			{OwningOUID: testOwningOU, Stage: StageReshare, TargetScope: TargetScopeOU,
				TargetOUID: "grandchildOfExcluded"},
		}, nil)

	visible, svcErr := suite.svc.IsShared(context.Background(), testResourceType, "role1", "grandchildOfExcluded")

	suite.Nil(svcErr)
	suite.False(visible)
}

func (suite *ServiceTestSuite) TestIsShared_ChainedDelegation_DeepExplicitHopsAllValid() {
	suite.resolver.ancestors["child1"] = []string{"root1"}
	suite.resolver.ancestors["grandchild1"] = []string{"child1", "root1"}
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{
			{OwningOUID: testOwningOU, Stage: StageShare, TargetScope: TargetScopeRoot, TargetOUID: "root1"},
			{OwningOUID: testOwningOU, Stage: StageReshare, TargetScope: TargetScopeOU, TargetOUID: "child1"},
			{OwningOUID: testOwningOU, Stage: StageReshare, TargetScope: TargetScopeOU, TargetOUID: "grandchild1"},
		}, nil)

	visible, svcErr := suite.svc.IsShared(context.Background(), testResourceType, "role1", "grandchild1")

	suite.Nil(svcErr)
	suite.True(visible)
}

func (suite *ServiceTestSuite) TestIsShared_NoGrantsAtAll_NotVisible() {
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{}, nil)

	visible, svcErr := suite.svc.IsShared(context.Background(), testResourceType, "role1", "ou1")

	suite.Nil(svcErr)
	suite.False(visible)
}

func (suite *ServiceTestSuite) TestIsShared_ResolverError() {
	suite.svc = newService(suite.mockStore, nil, &erroringResolver{}, suite.mockOUService, &fakeTransactioner{},
		nil, nil, nil, false).(*service)
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{{OwningOUID: testOwningOU, Stage: StageShare, TargetScope: TargetScopeAllRoots}}, nil)

	_, svcErr := suite.svc.IsShared(context.Background(), testResourceType, "role1", "ou1")

	suite.NotNil(svcErr)
}

func (suite *ServiceTestSuite) TestIsShared_StoreError() {
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return(nil, errBoom)

	_, svcErr := suite.svc.IsShared(context.Background(), testResourceType, "role1", "ou1")

	suite.NotNil(svcErr)
}

func (suite *ServiceTestSuite) TestListSharedResourceIDs_StoreError() {
	suite.mockStore.On("ListGrantsRelevantToChain", mock.Anything, testResourceType, []string{"ou1"}).
		Return(nil, errBoom)

	_, svcErr := suite.svc.ListSharedResourceIDs(context.Background(), testResourceType, "ou1")

	suite.NotNil(svcErr)
}

func (suite *ServiceTestSuite) TestListSharedResourceIDs_ExcludesOwnedIncludesShared() {
	suite.resolver.ancestors["child1"] = []string{"root1"}
	suite.mockStore.On("ListGrantsRelevantToChain", mock.Anything, testResourceType, []string{"root1", "child1"}).
		Return([]Grant{
			// role1 is shared to child1 via an all_children reshare anchored at root1.
			{ResourceID: "role1", OwningOUID: testOwningOU, Stage: StageShare,
				TargetScope: TargetScopeRoot, TargetOUID: "root1"},
			{ResourceID: "role1", OwningOUID: testOwningOU, Stage: StageReshare,
				TargetScope: TargetScopeAllChildren, TargetOUID: "root1"},
			// role2 is owned by child1 itself: even though its own grant nominally names child1,
			// it must be excluded from "shared to" results.
			{ResourceID: "role2", OwningOUID: "child1", Stage: StageReshare,
				TargetScope: TargetScopeAllChildren, TargetOUID: "child1"},
		}, nil)

	ids, svcErr := suite.svc.ListSharedResourceIDs(context.Background(), testResourceType, "child1")

	suite.Nil(svcErr)
	suite.Equal([]string{"role1"}, ids)
}

// --- Unshare ---

func (suite *ServiceTestSuite) TestUnshare_GrantNotFound() {
	suite.mockStore.On("GetGrant", mock.Anything, "missing").Return(Grant{}, ErrGrantNotFound)

	svcErr := suite.svc.Unshare(context.Background(), "missing")

	suite.NotNil(svcErr)
	suite.Equal(ErrorGrantNotFound.Code, svcErr.Code)
}

func (suite *ServiceTestSuite) TestUnshare_SingleOU_FiresHookOnceAndDeletes() {
	hookCalls := make([]string, 0)
	decl := &declarationWithHooks{
		fakeDeclaration: fakeDeclaration{resourceType: testResourceType},
		onUnshare: func(_ context.Context, resourceID, ouID string) error {
			hookCalls = append(hookCalls, resourceID+":"+ouID)
			return nil
		},
	}
	suite.svc.RegisterResourceType(decl)

	grant := Grant{ID: "grant1", ResourceType: testResourceType, ResourceID: "role1",
		Stage: StageReshare, TargetScope: TargetScopeOU, TargetOUID: "ou-sharee"}
	suite.mockStore.On("GetGrant", mock.Anything, "grant1").Return(grant, nil)
	suite.mockStore.On("ListChildGrants", mock.Anything, "grant1").Return([]Grant{}, nil)
	suite.mockStore.On("DeleteGrant", mock.Anything, "grant1").Return(nil)

	svcErr := suite.svc.Unshare(context.Background(), "grant1")

	suite.Nil(svcErr)
	suite.Equal([]string{"role1:ou-sharee"}, hookCalls)
}

func (suite *ServiceTestSuite) TestUnshare_ProcessesChildGrantsBeforeParent() {
	var order []string
	decl := &declarationWithHooks{
		fakeDeclaration: fakeDeclaration{resourceType: testResourceType},
		onUnshare: func(_ context.Context, resourceID, ouID string) error {
			order = append(order, "hook:"+ouID)
			return nil
		},
	}
	suite.svc.RegisterResourceType(decl)

	parent := Grant{ID: "parent", ResourceType: testResourceType, ResourceID: "role1",
		Stage: StageShare, TargetScope: TargetScopeRoot, TargetOUID: "root1"}
	child := Grant{ID: "child", ResourceType: testResourceType, ResourceID: "role1",
		Stage: StageReshare, TargetScope: TargetScopeOU, TargetOUID: "ou-child", ParentGrantID: "parent"}

	suite.mockStore.On("GetGrant", mock.Anything, "parent").Return(parent, nil)
	suite.mockStore.On("GetGrant", mock.Anything, "child").Return(child, nil)
	suite.mockStore.On("ListChildGrants", mock.Anything, "parent").Return([]Grant{child}, nil)
	suite.mockStore.On("ListChildGrants", mock.Anything, "child").Return([]Grant{}, nil)
	suite.mockStore.On("DeleteGrant", mock.Anything, "child").
		Run(func(_ mock.Arguments) { order = append(order, "delete:child") }).Return(nil)
	suite.mockStore.On("DeleteGrant", mock.Anything, "parent").
		Run(func(_ mock.Arguments) { order = append(order, "delete:parent") }).Return(nil)

	svcErr := suite.svc.Unshare(context.Background(), "parent")

	suite.Nil(svcErr)
	suite.Equal([]string{"hook:ou-child", "delete:child", "hook:root1", "delete:parent"}, order)
}

func (suite *ServiceTestSuite) TestUnshare_AllChildren_EnumeratesSubtreeViaOUService() {
	var hookedOUs []string
	decl := &declarationWithHooks{
		fakeDeclaration: fakeDeclaration{resourceType: testResourceType},
		onUnshare: func(_ context.Context, _ string, ouID string) error {
			hookedOUs = append(hookedOUs, ouID)
			return nil
		},
	}
	suite.svc.RegisterResourceType(decl)

	grant := Grant{ID: "grant1", ResourceType: testResourceType, ResourceID: "role1",
		Stage: StageReshare, TargetScope: TargetScopeAllChildren, TargetOUID: "root1"}
	suite.mockStore.On("GetGrant", mock.Anything, "grant1").Return(grant, nil)
	suite.mockStore.On("ListChildGrants", mock.Anything, "grant1").Return([]Grant{}, nil)
	suite.mockStore.On("DeleteGrant", mock.Anything, "grant1").Return(nil)

	suite.mockOUService.On("GetOrganizationUnitChildren",
		mock.Anything, "root1", mock.Anything, 0, (*tidcommon.FilterGroup)(nil)).
		Return(&providers.OrganizationUnitListResponse{
			TotalResults:      1,
			OrganizationUnits: []providers.OrganizationUnitBasic{{ID: "child1"}},
		}, nil)
	suite.mockOUService.On("GetOrganizationUnitChildren",
		mock.Anything, "child1", mock.Anything, 0, (*tidcommon.FilterGroup)(nil)).
		Return(&providers.OrganizationUnitListResponse{TotalResults: 0}, nil)

	svcErr := suite.svc.Unshare(context.Background(), "grant1")

	suite.Nil(svcErr)
	suite.Equal([]string{"child1"}, hookedOUs)
}

func (suite *ServiceTestSuite) TestUnshare_AllChildren_SkipsExcludedSubtree() {
	var hookedOUs []string
	decl := &declarationWithHooks{
		fakeDeclaration: fakeDeclaration{resourceType: testResourceType},
		onUnshare: func(_ context.Context, _ string, ouID string) error {
			hookedOUs = append(hookedOUs, ouID)
			return nil
		},
	}
	suite.svc.RegisterResourceType(decl)

	// "excludedChild" was carved out of the all_children grant, so its own subtree
	// ("grandchildOfExcluded") was never made visible either and must not be walked into or hooked.
	grant := Grant{ID: "grant1", ResourceType: testResourceType, ResourceID: "role1",
		Stage: StageReshare, TargetScope: TargetScopeAllChildren, TargetOUID: "root1",
		ExcludedOUIDs: []string{"excludedChild"}}
	suite.mockStore.On("GetGrant", mock.Anything, "grant1").Return(grant, nil)
	suite.mockStore.On("ListChildGrants", mock.Anything, "grant1").Return([]Grant{}, nil)
	suite.mockStore.On("DeleteGrant", mock.Anything, "grant1").Return(nil)

	suite.mockOUService.On("GetOrganizationUnitChildren",
		mock.Anything, "root1", mock.Anything, 0, (*tidcommon.FilterGroup)(nil)).
		Return(&providers.OrganizationUnitListResponse{
			TotalResults: 2,
			OrganizationUnits: []providers.OrganizationUnitBasic{
				{ID: "excludedChild"}, {ID: "includedChild"},
			},
		}, nil)
	suite.mockOUService.On("GetOrganizationUnitChildren",
		mock.Anything, "includedChild", mock.Anything, 0, (*tidcommon.FilterGroup)(nil)).
		Return(&providers.OrganizationUnitListResponse{TotalResults: 0}, nil)
	// Deliberately no stub for GetOrganizationUnitChildren("excludedChild", ...): if the walk ever
	// enters the excluded subtree, the mock call goes unmatched and this test fails loudly.

	svcErr := suite.svc.Unshare(context.Background(), "grant1")

	suite.Nil(svcErr)
	suite.Equal([]string{"includedChild"}, hookedOUs)
}

func (suite *ServiceTestSuite) TestUnshare_AllRoots_DoesNotEnumerateAndFiresNoHook() {
	called := false
	decl := &declarationWithHooks{
		fakeDeclaration: fakeDeclaration{resourceType: testResourceType},
		onUnshare: func(_ context.Context, _, _ string) error {
			called = true
			return nil
		},
	}
	suite.svc.RegisterResourceType(decl)

	grant := Grant{ID: "grant1", ResourceType: testResourceType, ResourceID: "role1",
		Stage: StageShare, TargetScope: TargetScopeAllRoots}
	suite.mockStore.On("GetGrant", mock.Anything, "grant1").Return(grant, nil)
	suite.mockStore.On("ListChildGrants", mock.Anything, "grant1").Return([]Grant{}, nil)
	suite.mockStore.On("DeleteGrant", mock.Anything, "grant1").Return(nil)

	svcErr := suite.svc.Unshare(context.Background(), "grant1")

	suite.Nil(svcErr)
	suite.False(called, "all-roots unshare is a documented scope reduction: no retroactive enumeration")
}

// declarationWithHooks composes fakeDeclaration with a configurable SharingHooks.OnUnshare.
type declarationWithHooks struct {
	fakeDeclaration
	onUnshare func(ctx context.Context, resourceID, ouID string) error
}

func (d *declarationWithHooks) OnUnshare(ctx context.Context, resourceID, ouID string) error {
	return d.onUnshare(ctx, resourceID, ouID)
}

// --- RequireOwnership ---

func (suite *ServiceTestSuite) TestRequireOwnership_OwnerMatch_Allowed() {
	ctx := requireOwnershipContext(testOwningOU, false)

	svcErr := suite.svc.RequireOwnership(ctx, testResourceType, testOwningOU)

	suite.Nil(svcErr)
}

func (suite *ServiceTestSuite) TestRequireOwnership_RootPermission_AllowedRegardlessOfOU() {
	ctx := requireOwnershipContext("some-other-ou", true)

	svcErr := suite.svc.RequireOwnership(ctx, testResourceType, testOwningOU)

	suite.Nil(svcErr)
}

func (suite *ServiceTestSuite) TestRequireOwnership_Mismatch_Rejected() {
	ctx := requireOwnershipContext("sharee-ou", false)

	svcErr := suite.svc.RequireOwnership(ctx, testResourceType, testOwningOU)

	suite.NotNil(svcErr)
	suite.Equal(ErrorCoreConfigOwnerOnly.Code, svcErr.Code)
}

// --- RequireOwnershipForDeletion ---

func (suite *ServiceTestSuite) TestRequireOwnershipForDeletion_OwnerMatch_Allowed() {
	ctx := requireOwnershipContext(testOwningOU, false)

	svcErr := suite.svc.RequireOwnershipForDeletion(ctx, testResourceType, testOwningOU)

	suite.Nil(svcErr)
}

func (suite *ServiceTestSuite) TestRequireOwnershipForDeletion_RootPermission_AllowedRegardlessOfOU() {
	ctx := requireOwnershipContext("some-other-ou", true)

	svcErr := suite.svc.RequireOwnershipForDeletion(ctx, testResourceType, testOwningOU)

	suite.Nil(svcErr)
}

// TestRequireOwnershipForDeletion_Mismatch_FallsBackToGenericError proves a resource type that
// doesn't implement DeletionOwnershipError (fakeDeclaration doesn't) still gets the generic
// ErrorCoreConfigOwnerOnly, same as RequireOwnership — the new method changes nothing for
// resource types that haven't opted into a more specific error.
func (suite *ServiceTestSuite) TestRequireOwnershipForDeletion_Mismatch_FallsBackToGenericError() {
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	ctx := requireOwnershipContext("sharee-ou", false)

	svcErr := suite.svc.RequireOwnershipForDeletion(ctx, testResourceType, testOwningOU)

	suite.NotNil(svcErr)
	suite.Equal(ErrorCoreConfigOwnerOnly.Code, svcErr.Code)
}

// TestRequireOwnershipForDeletion_Mismatch_UsesResourceTypeSpecificError proves a resource type
// that does implement DeletionOwnershipError gets its own error instead of the generic one.
func (suite *ServiceTestSuite) TestRequireOwnershipForDeletion_Mismatch_UsesResourceTypeSpecificError() {
	roleSpecificErr := &tidcommon.ServiceError{Type: tidcommon.ClientErrorType, Code: "ROL-1024"}
	suite.svc.RegisterResourceType(&fakeDeclarationWithDeletionError{
		fakeDeclaration: fakeDeclaration{resourceType: testResourceType},
		err:             roleSpecificErr,
	})
	ctx := requireOwnershipContext("sharee-ou", false)

	svcErr := suite.svc.RequireOwnershipForDeletion(ctx, testResourceType, testOwningOU)

	suite.NotNil(svcErr)
	suite.Equal("ROL-1024", svcErr.Code)
}

// TestRequireOwnershipForDeletion_UnregisteredResourceType_FallsBackToGenericError proves the
// registry lookup miss is handled the same as "no override implemented", not an internal error.
func (suite *ServiceTestSuite) TestRequireOwnershipForDeletion_UnregisteredResourceType_FallsBackToGenericError() {
	ctx := requireOwnershipContext("sharee-ou", false)

	svcErr := suite.svc.RequireOwnershipForDeletion(ctx, testResourceType, testOwningOU)

	suite.NotNil(svcErr)
	suite.Equal(ErrorCoreConfigOwnerOnly.Code, svcErr.Code)
}

// --- Declarative grants ---

// ShareDeclarativeTestSuite proves a grant declared by a declarative resource file is validated
// exactly as an API-created one but held in memory rather than written to RESOURCE_GRANT.
type ShareDeclarativeTestSuite struct {
	suite.Suite
	mockStore   *sharingStoreInterfaceMock
	mockOU      *oumock.OrganizationUnitServiceInterfaceMock
	resolver    *fakeOUHierarchyResolver
	declarative *declarativeGrantStore
	svc         *service
}

func TestShareDeclarativeTestSuite(t *testing.T) {
	suite.Run(t, new(ShareDeclarativeTestSuite))
}

func (suite *ShareDeclarativeTestSuite) SetupTest() {
	suite.mockStore = newSharingStoreInterfaceMock(suite.T())
	suite.mockOU = oumock.NewOrganizationUnitServiceInterfaceMock(suite.T())
	suite.resolver = &fakeOUHierarchyResolver{ancestors: map[string][]string{}}
	suite.declarative = newDeclarativeGrantStore()
	suite.svc = newService(
		newCompositeSharingStore(suite.mockStore, suite.declarative), suite.declarative,
		suite.resolver, suite.mockOU, &fakeTransactioner{}, nil, nil, nil, false,
	).(*service)
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
	// The target is a direct child of the owning organization unit, which is what
	// children-targeting requires.
	suite.resolver.ancestors[testChildOU] = []string{"ou1"}
}

// The point of the whole change: nothing reaches the database. CreateGrant is never stubbed, so
// the mock fails the test if the service tries to persist.
func (suite *ShareDeclarativeTestSuite) TestSeedsInMemoryAndNeverPersists() {
	grants, svcErr := suite.svc.ShareDeclarative(
		context.Background(), testResourceType, "role1", "ou1", "ou1",
		SharePolicy{OUIDs: []string{testChildOU}},
	)

	suite.Nil(svcErr)
	suite.Require().Len(grants, 1)
	suite.mockStore.AssertNotCalled(suite.T(), "CreateGrant", mock.Anything, mock.Anything)

	// And it reads back through the composite store, so it is a real, resolvable grant.
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{}, nil)
	listed, svcErr := suite.svc.ListGrants(context.Background(), testResourceType, "role1")
	suite.Nil(svcErr)
	suite.Require().Len(listed, 1)
	suite.Equal(grants[0].ID, listed[0].ID)
	suite.Equal(testChildOU, listed[0].TargetOUID)
}

// The same validation Share applies still runs: an acting OU with no standing is refused, so a bad
// declarative file fails at startup rather than loading a grant the API would have rejected.
func (suite *ShareDeclarativeTestSuite) TestAppliesTheSameValidationAsShare() {
	// Neither mode selected is malformed, exactly as it is through Share.
	_, svcErr := suite.svc.ShareDeclarative(
		context.Background(), testResourceType, "role1", "ou1", "ou1", SharePolicy{},
	)

	suite.NotNil(svcErr)
	suite.Equal(ErrorInvalidRequestFormat.Code, svcErr.Code)
	suite.Empty(suite.declarative.ListGrantsForResource(testResourceType, "role1"))
}

// A declared grant is owned by its file, so the API cannot revoke it.
func (suite *ShareDeclarativeTestSuite) TestUnshareRefusesADeclaredGrant() {
	grants, svcErr := suite.svc.ShareDeclarative(
		context.Background(), testResourceType, "role1", "ou1", "ou1",
		SharePolicy{OUIDs: []string{testChildOU}},
	)
	suite.Require().Nil(svcErr)
	suite.Require().Len(grants, 1)

	svcErr = suite.svc.Unshare(context.Background(), grants[0].ID)

	suite.NotNil(svcErr)
	suite.Equal(ErrorGrantDeclarative.Code, svcErr.Code)
	// Refused before any descendant lookup or deletion is attempted.
	suite.mockStore.AssertNotCalled(suite.T(), "DeleteGrant", mock.Anything, mock.Anything)
	suite.mockStore.AssertNotCalled(suite.T(), "ListChildGrants", mock.Anything, mock.Anything)
}

// Declarative resources disabled means no in-memory store, so a declared grant is a wiring bug
// rather than something to silently persist.
func (suite *ShareDeclarativeTestSuite) TestRefusesWhenDeclarativeStoreAbsent() {
	svc := newService(suite.mockStore, nil, suite.resolver, suite.mockOU, &fakeTransactioner{},
		nil, nil, nil, false).(*service)
	svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})

	_, svcErr := svc.ShareDeclarative(
		context.Background(), testResourceType, "role1", "ou1", "ou1",
		SharePolicy{OUIDs: []string{testChildOU}},
	)

	suite.NotNil(svcErr)
	suite.Equal(tidcommon.InternalServerError.Code, svcErr.Code)
	suite.mockStore.AssertNotCalled(suite.T(), "CreateGrant", mock.Anything, mock.Anything)
}

// A sharee resharing what a declarative file granted it is an ordinary API share, and must work.
// Its lineage link is dropped, though: RESOURCE_GRANT.PARENT_GRANT_ID is a foreign key onto the
// same table, and the declared parent is held in memory, so the insert would fail if it were set.
func (suite *ShareDeclarativeTestSuite) TestReshareOfADeclaredGrantPersistsWithoutParent() {
	// Root declaratively grants role1 to child1, then child1 reshares to its own child.
	declared, svcErr := suite.svc.ShareDeclarative(
		context.Background(), testResourceType, "role1", "ou1", "ou1",
		SharePolicy{OUIDs: []string{testChildOU}},
	)
	suite.Require().Nil(svcErr)
	suite.Require().Len(declared, 1)

	suite.resolver.ancestors["grandchild1"] = []string{testChildOU, "ou1"}
	suite.mockStore.On("ListGrantsForResource", mock.Anything, testResourceType, "role1").
		Return([]Grant{}, nil)
	suite.mockStore.On("CreateGrant", mock.Anything, mock.MatchedBy(func(g Grant) bool {
		return g.Stage == StageReshare && g.TargetOUID == "grandchild1" && g.ParentGrantID == ""
	})).Return(nil)

	grants, svcErr := suite.svc.Share(
		context.Background(), testResourceType, "role1", "ou1", testChildOU,
		SharePolicy{OUIDs: []string{"grandchild1"}},
	)

	suite.Nil(svcErr)
	suite.Require().Len(grants, 1)
	suite.Equal(StageReshare, grants[0].Stage)
	suite.Empty(grants[0].ParentGrantID)
}

// The owner sharing its own declaratively defined resource through the API is a first-hop grant
// with no parent at all, and is persisted like any other.
func (suite *ShareDeclarativeTestSuite) TestOwnerCanShareADeclarativeResourceViaAPI() {
	suite.mockStore.On("CreateGrant", mock.Anything, mock.MatchedBy(func(g Grant) bool {
		return g.Stage == StageShare && g.TargetOUID == testChildOU && g.ParentGrantID == ""
	})).Return(nil)

	grants, svcErr := suite.svc.Share(
		context.Background(), testResourceType, "role1", "ou1", "ou1",
		SharePolicy{OUIDs: []string{testChildOU}},
	)

	suite.Nil(svcErr)
	suite.Len(grants, 1)
}

// --- ou_subtree: share one named branch, whole ---

// SubtreeShareTestSuite covers TargetScopeOUSubtree, which grants a named direct child together
// with its entire subtree — the middle ground between `ouIds` (that child alone) and `allChildren`
// (every branch the issuer has).
type SubtreeShareTestSuite struct {
	suite.Suite
	mockStore *sharingStoreInterfaceMock
	mockOU    *oumock.OrganizationUnitServiceInterfaceMock
	resolver  *fakeOUHierarchyResolver
	svc       *service
}

func TestSubtreeShareTestSuite(t *testing.T) {
	suite.Run(t, new(SubtreeShareTestSuite))
}

func (suite *SubtreeShareTestSuite) SetupTest() {
	suite.mockStore = newSharingStoreInterfaceMock(suite.T())
	suite.mockOU = oumock.NewOrganizationUnitServiceInterfaceMock(suite.T())
	// owner-ou -> child1 -> grandchild1 -> greatgrandchild1, plus a sibling branch under the owner.
	suite.resolver = &fakeOUHierarchyResolver{ancestors: map[string][]string{
		testChildOU:        {testOwningOU},
		"grandchild1":      {testChildOU, testOwningOU},
		"greatgrandchild1": {"grandchild1", testChildOU, testOwningOU},
		"sibling1":         {testOwningOU},
		"sibling1-child":   {"sibling1", testOwningOU},
	}}
	suite.svc = newService(suite.mockStore, nil, suite.resolver, suite.mockOU, &fakeTransactioner{},
		nil, nil, nil, false).(*service)
	suite.svc.RegisterResourceType(&fakeDeclaration{resourceType: testResourceType})
}

// subtreeGrant is the grant an owner's `subtreeOuIds: [child1]` call produces.
func subtreeGrant(excluded ...string) Grant {
	return Grant{
		ID: "g-subtree", ResourceType: testResourceType, ResourceID: "role1",
		OwningOUID: testOwningOU, Stage: StageShare,
		TargetScope: TargetScopeOUSubtree, TargetOUID: testChildOU, ExcludedOUIDs: excluded,
	}
}

func (suite *SubtreeShareTestSuite) TestCreatesOneGrantPerNamedChild() {
	suite.mockStore.On("CreateGrant", mock.Anything, mock.MatchedBy(func(g Grant) bool {
		return g.TargetScope == TargetScopeOUSubtree && g.TargetOUID == testChildOU &&
			g.Stage == StageShare && g.ParentGrantID == ""
	})).Return(nil)

	grants, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1",
		testOwningOU, testOwningOU, SharePolicy{SubtreeOUIDs: []string{testChildOU}})

	suite.Nil(svcErr)
	suite.Require().Len(grants, 1)
	suite.Equal(TargetScopeOUSubtree, grants[0].TargetScope)
}

// The same one-hop rule as ouIds: an issuer may only name its own direct child, so a grandchild is
// rejected rather than silently granted.
func (suite *SubtreeShareTestSuite) TestRejectsATargetThatIsNotADirectChild() {
	_, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1",
		testOwningOU, testOwningOU, SharePolicy{SubtreeOUIDs: []string{"grandchild1"}})

	suite.NotNil(svcErr)
	suite.Equal(ErrorInvalidTargetOU.Code, svcErr.Code)
	suite.mockStore.AssertNotCalled(suite.T(), "CreateGrant", mock.Anything, mock.Anything)
}

// SubtreeOUIDs alone is a valid children-targeting request; it must not be read as "no mode".
func (suite *SubtreeShareTestSuite) TestSelectsChildrenTargetingMode() {
	_, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1",
		testOwningOU, testOwningOU, SharePolicy{
			SubtreeOUIDs: []string{testChildOU}, RootOUIDs: []string{"root1"},
		})

	// Both modes populated is malformed, which is only reachable if SubtreeOUIDs registers as
	// children-targeting in the first place.
	suite.NotNil(svcErr)
	suite.Equal(ErrorInvalidRequestFormat.Code, svcErr.Code)
}

func (suite *SubtreeShareTestSuite) TestCoversTheNamedChildItself() {
	visible, _, grant := evaluateChainVisibility(
		[]string{testOwningOU, testChildOU}, []Grant{subtreeGrant()})

	suite.True(visible)
	suite.Require().NotNil(grant)
	suite.Equal(TargetScopeOUSubtree, grant.TargetScope)
}

func (suite *SubtreeShareTestSuite) TestCoversDescendantsAtAnyDepth() {
	for _, chain := range [][]string{
		{testOwningOU, testChildOU, "grandchild1"},
		{testOwningOU, testChildOU, "grandchild1", "greatgrandchild1"},
	} {
		visible, _, _ := evaluateChainVisibility(chain, []Grant{subtreeGrant()})
		suite.True(visible, "expected %v to be covered", chain)
	}
}

// The whole point of the scope: it reaches one branch, not every branch the issuer owns.
func (suite *SubtreeShareTestSuite) TestDoesNotCoverASiblingBranch() {
	for _, chain := range [][]string{
		{testOwningOU, "sibling1"},
		{testOwningOU, "sibling1", "sibling1-child"},
	} {
		visible, _, _ := evaluateChainVisibility(chain, []Grant{subtreeGrant()})
		suite.False(visible, "expected %v not to be covered", chain)
	}
}

func (suite *SubtreeShareTestSuite) TestExclusionCutsOffThatOUAndBelow() {
	grants := []Grant{subtreeGrant("grandchild1")}

	// The named child is still covered; the excluded OU and everything under it is not.
	visible, _, _ := evaluateChainVisibility([]string{testOwningOU, testChildOU}, grants)
	suite.True(visible)
	visible, _, _ = evaluateChainVisibility([]string{testOwningOU, testChildOU, "grandchild1"}, grants)
	suite.False(visible)
	visible, _, _ = evaluateChainVisibility(
		[]string{testOwningOU, testChildOU, "grandchild1", "greatgrandchild1"}, grants)
	suite.False(visible)
}

// An exclusion naming an OU outside this grant's own subtree can never sit between the anchor and a
// descendant of it, so carrying it on every subtree grant is inert rather than wrong.
func (suite *SubtreeShareTestSuite) TestExclusionOutsideTheSubtreeIsInert() {
	grants := []Grant{subtreeGrant("sibling1")}

	visible, _, _ := evaluateChainVisibility(
		[]string{testOwningOU, testChildOU, "grandchild1"}, grants)

	suite.True(visible)
}

func (suite *SubtreeShareTestSuite) TestRejectsAnExclusionOutsideTheActingSubtree() {
	suite.resolver.ancestors["stranger"] = []string{"other-root"}

	_, svcErr := suite.svc.Share(context.Background(), testResourceType, "role1",
		testOwningOU, testOwningOU, SharePolicy{
			SubtreeOUIDs: []string{testChildOU}, ExcludedOUIDs: []string{"stranger"},
		})

	suite.NotNil(svcErr)
	suite.Equal(ErrorInvalidTargetOU.Code, svcErr.Code)
}

// Export round-trips the scope, so a subtree grant survives declarative export/import unchanged.
func (suite *SubtreeShareTestSuite) TestPolicyFromGrantRoundTripsTheScope() {
	policy := policyFromGrant(subtreeGrant("grandchild1"))

	suite.Equal([]string{testChildOU}, policy.SubtreeOUIDs)
	suite.Equal([]string{"grandchild1"}, policy.ExcludedOUIDs)
	suite.False(policy.AllChildren)
	suite.Empty(policy.OUIDs)
}

// Unsharing must fire OnUnshare for the anchor as well as its subtree; listSubtreeOUIDs alone
// enumerates below the anchor only.
func (suite *SubtreeShareTestSuite) TestResolveGrantOUIDsIncludesTheAnchor() {
	suite.mockOU.EXPECT().GetOrganizationUnitChildren(
		mock.Anything, testChildOU, mock.Anything, 0, (*tidcommon.FilterGroup)(nil)).
		Return(&providers.OrganizationUnitListResponse{
			OrganizationUnits: []providers.OrganizationUnitBasic{{ID: "grandchild1"}},
		}, nil)
	suite.mockOU.EXPECT().GetOrganizationUnitChildren(
		mock.Anything, "grandchild1", mock.Anything, 0, (*tidcommon.FilterGroup)(nil)).
		Return(&providers.OrganizationUnitListResponse{}, nil)

	ouIDs, svcErr := suite.svc.resolveGrantOUIDs(context.Background(), subtreeGrant())

	suite.Nil(svcErr)
	suite.Equal([]string{testChildOU, "grandchild1"}, ouIDs)
}
