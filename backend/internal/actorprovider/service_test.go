// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package actorprovider

import (
	"context"
	"errors"
	"testing"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/entityprovider"
	"github.com/thunder-id/thunderid/internal/inboundclient"
	inboundmodel "github.com/thunder-id/thunderid/internal/inboundclient/model"
	syscontext "github.com/thunder-id/thunderid/internal/system/context"
	"github.com/thunder-id/thunderid/tests/mocks/authnprovider/managermock"
	"github.com/thunder-id/thunderid/tests/mocks/entityprovidermock"
	"github.com/thunder-id/thunderid/tests/mocks/inboundclientmock"
	"github.com/thunder-id/thunderid/tests/mocks/rolemock"
)

type ActorProviderTestSuite struct {
	suite.Suite
	mockInbound *inboundclientmock.InboundClientServiceInterfaceMock
	mockEntity  *entityprovidermock.EntityProviderInterfaceMock
	mockAuthn   *managermock.AuthnProviderManagerMock
	mockRole    *rolemock.RoleServiceInterfaceMock
	provider    providers.ActorProvider
}

func TestActorProviderTestSuite(t *testing.T) {
	suite.Run(t, new(ActorProviderTestSuite))
}

func (s *ActorProviderTestSuite) SetupTest() {
	s.mockInbound = inboundclientmock.NewInboundClientServiceInterfaceMock(s.T())
	s.mockEntity = entityprovidermock.NewEntityProviderInterfaceMock(s.T())
	s.mockAuthn = managermock.NewAuthnProviderManagerMock(s.T())
	s.mockRole = rolemock.NewRoleServiceInterfaceMock(s.T())
	s.provider = Initialize(s.mockInbound, s.mockEntity, s.mockAuthn, s.mockRole, nil)
}

func (s *ActorProviderTestSuite) TestGetOAuthClientByClientID_Delegates() {
	expected := &providers.OAuthClient{ID: "app-1", ClientID: "client-1"}
	s.mockInbound.On("GetOAuthClientByClientID", mock.Anything, "client-1").Return(expected, nil)

	client, svcErr := s.provider.GetOAuthClientByClientID(context.Background(), "client-1")

	s.Nil(svcErr)
	s.Equal(toProviderOAuthClient(expected), client)
}

func (s *ActorProviderTestSuite) TestGetOAuthClientByClientID_NotFound() {
	s.mockInbound.On("GetOAuthClientByClientID", mock.Anything, "missing").
		Return((*providers.OAuthClient)(nil), inboundclient.ErrInboundClientNotFound)

	client, svcErr := s.provider.GetOAuthClientByClientID(context.Background(), "missing")

	s.Nil(client)
	s.Equal(ErrorActorNotFound.Code, svcErr.Code)
}

func (s *ActorProviderTestSuite) TestGetOAuthClientByClientID_FetchFailed() {
	s.mockInbound.On("GetOAuthClientByClientID", mock.Anything, "client-1").
		Return((*providers.OAuthClient)(nil), errors.New("db error"))

	client, svcErr := s.provider.GetOAuthClientByClientID(context.Background(), "client-1")

	s.Nil(client)
	s.Equal(tidcommon.InternalServerError.Code, svcErr.Code)
}

func (s *ActorProviderTestSuite) TestGetInboundClientByID_NotFound() {
	s.mockInbound.On("GetInboundClientByEntityID", mock.Anything, "missing").
		Return((*inboundmodel.InboundClient)(nil), inboundclient.ErrInboundClientNotFound)

	client, svcErr := s.provider.GetInboundClientByID(context.Background(), "missing")

	s.Nil(client)
	s.Equal(ErrorActorNotFound.Code, svcErr.Code)
}

func (s *ActorProviderTestSuite) TestGetInboundClientByID_FetchFailed() {
	s.mockInbound.On("GetInboundClientByEntityID", mock.Anything, "app-1").
		Return((*inboundmodel.InboundClient)(nil), errors.New("db error"))

	client, svcErr := s.provider.GetInboundClientByID(context.Background(), "app-1")

	s.Nil(client)
	s.Equal(tidcommon.InternalServerError.Code, svcErr.Code)
}

func (s *ActorProviderTestSuite) TestGetInboundClientByID_Delegates() {
	expected := &inboundmodel.InboundClient{ID: "app-1"}
	s.mockInbound.On("GetInboundClientByEntityID", mock.Anything, "app-1").Return(expected, nil)

	client, svcErr := s.provider.GetInboundClientByID(context.Background(), "app-1")

	s.Nil(svcErr)
	s.Equal(expected, client)
}

func (s *ActorProviderTestSuite) TestAuthenticateActor_Delegates_Success() {
	identifiers := map[string]interface{}{"userID": "app-1"}
	creds := map[string]interface{}{"flowSecret": "s3cret"}
	s.mockAuthn.On("AuthenticateUser", mock.Anything,
		identifiers, creds,
		(*providers.RequestedAttributes)(nil), (*providers.AuthnMetadata)(nil),
		providers.AuthUser{}).
		Return(providers.AuthUser{}, providers.AuthenticatedClaims(nil),
			(*tidcommon.ServiceError)(nil))

	svcErr := s.provider.AuthenticateActor(context.Background(), identifiers, creds)

	s.Nil(svcErr)
}

func (s *ActorProviderTestSuite) TestAuthenticateActor_Delegates_Failure() {
	identifiers := map[string]interface{}{"userID": "app-1"}
	creds := map[string]interface{}{"flowSecret": "wrong"}
	authFailed := &tidcommon.ServiceError{Code: "AUTH-FAIL", Type: tidcommon.ClientErrorType}
	s.mockAuthn.On("AuthenticateUser", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything).
		Return(providers.AuthUser{}, providers.AuthenticatedClaims(nil), authFailed)

	svcErr := s.provider.AuthenticateActor(context.Background(), identifiers, creds)

	s.NotNil(svcErr)
	s.Equal("AUTH-FAIL", svcErr.Code)
}

func (s *ActorProviderTestSuite) TestGetActor_Delegates() {
	expected := &providers.Entity{ID: "app-1"}
	s.mockEntity.On("GetEntity", "app-1").Return(expected, (*entityprovider.EntityProviderError)(nil))

	entity, err := s.provider.GetActor("app-1")

	s.Nil(err)
	s.Equal(expected, entity)
}

func (s *ActorProviderTestSuite) TestGetActorGroups_Delegates() {
	expected := []providers.EntityGroup{{ID: "group-1"}}
	s.mockEntity.On("GetTransitiveEntityGroups", "app-1").Return(expected, (*entityprovider.EntityProviderError)(nil))

	groups, err := s.provider.GetActorGroups("app-1")

	s.Nil(err)
	s.Equal(expected, groups)
}

func (s *ActorProviderTestSuite) TestGetActorRoles_Delegates() {
	expected := []string{"admin", "editor"}
	groupIDs := []string{"group-1"}
	s.mockRole.On("GetUserRoles", mock.Anything, "app-1", groupIDs).
		Return(expected, (*tidcommon.ServiceError)(nil))

	roles, err := s.provider.GetActorRoles("app-1", groupIDs)

	s.Nil(err)
	s.Equal(expected, roles)
}

func (s *ActorProviderTestSuite) TestGetActorRoles_PropagatesError() {
	svcErr := &tidcommon.ServiceError{
		Code:  "ROLE-0001",
		Error: tidcommon.I18nMessage{Key: "error.test.role", DefaultValue: "role lookup failed"},
	}
	s.mockRole.On("GetUserRoles", mock.Anything, "app-1", []string{"group-1"}).Return(nil, svcErr)

	roles, err := s.provider.GetActorRoles("app-1", []string{"group-1"})

	s.Nil(roles)
	s.Equal(svcErr, err)
}

func (s *ActorProviderTestSuite) TestGetActorRoles_NilRoleService_ReturnsNil() {
	provider := Initialize(s.mockInbound, s.mockEntity, s.mockAuthn, nil, nil)

	roles, err := provider.GetActorRoles("app-1", []string{"group-1"})

	s.Nil(err)
	s.Nil(roles)
}

// --- Accessing-organization-unit scoping at client resolution ---

// AccessingOUResolutionTestSuite covers the rule that a client only resolves against an
// organization unit it may actually be used in. This lives at resolution rather than in a grant
// handler so that every OAuth path inheriting client resolution inherits the rule with it.
type AccessingOUResolutionTestSuite struct {
	suite.Suite
	mockInbound *inboundclientmock.InboundClientServiceInterfaceMock
	mockAccess  *ApplicationOUAccessCheckerMock
	provider    providers.ActorProvider
}

func TestAccessingOUResolutionTestSuite(t *testing.T) {
	suite.Run(t, new(AccessingOUResolutionTestSuite))
}

func (s *AccessingOUResolutionTestSuite) SetupTest() {
	s.mockInbound = inboundclientmock.NewInboundClientServiceInterfaceMock(s.T())
	s.mockAccess = NewApplicationOUAccessCheckerMock(s.T())
	s.provider = Initialize(
		s.mockInbound,
		entityprovidermock.NewEntityProviderInterfaceMock(s.T()),
		managermock.NewAuthnProviderManagerMock(s.T()),
		rolemock.NewRoleServiceInterfaceMock(s.T()),
		s.mockAccess,
	)
}

// expectClient stubs the underlying lookup for the fixture application, owned by "owner-ou".
func (s *AccessingOUResolutionTestSuite) expectClient() {
	s.mockInbound.On("GetOAuthClientByClientID", mock.Anything, "client-1").
		Return(&providers.OAuthClient{ID: "app-1", ClientID: "client-1", OUID: "owner-ou"}, nil)
}

// A request with no /ou/ prefix carries no accessing organization unit, so nothing is consulted
// and resolution behaves exactly as it did before this rule existed.
func (s *AccessingOUResolutionTestSuite) TestNoAccessingOUResolvesWithoutConsultingGrants() {
	s.expectClient()

	client, svcErr := s.provider.GetOAuthClientByClientID(context.Background(), "client-1")

	s.Nil(svcErr)
	s.Require().NotNil(client)
	s.mockAccess.AssertNotCalled(s.T(), "IsApplicationGrantedToOU", mock.Anything, mock.Anything, mock.Anything)
}

// The owning organization unit needs no grant of its own, so it must not even be asked for one.
func (s *AccessingOUResolutionTestSuite) TestOwningOUResolvesWithoutAGrant() {
	s.expectClient()
	ctx := syscontext.WithAccessingOUID(context.Background(), "owner-ou")

	client, svcErr := s.provider.GetOAuthClientByClientID(ctx, "client-1")

	s.Nil(svcErr)
	s.Require().NotNil(client)
	s.mockAccess.AssertNotCalled(s.T(), "IsApplicationGrantedToOU", mock.Anything, mock.Anything, mock.Anything)
}

func (s *AccessingOUResolutionTestSuite) TestGrantedOUResolves() {
	s.expectClient()
	s.mockAccess.EXPECT().IsApplicationGrantedToOU(mock.Anything, "app-1", "other-ou").Return(true, nil)
	ctx := syscontext.WithAccessingOUID(context.Background(), "other-ou")

	client, svcErr := s.provider.GetOAuthClientByClientID(ctx, "client-1")

	s.Nil(svcErr)
	s.Require().NotNil(client)
	s.Equal("app-1", client.ID)
}

// The refusal is ErrorUnauthorized rather than a not-found: the client authenticated, it simply has
// no standing here, and the OAuth client-auth layer turns exactly this into unauthorized_client.
func (s *AccessingOUResolutionTestSuite) TestUngrantedOUDoesNotResolve() {
	s.expectClient()
	s.mockAccess.EXPECT().IsApplicationGrantedToOU(mock.Anything, "app-1", "other-ou").Return(false, nil)
	ctx := syscontext.WithAccessingOUID(context.Background(), "other-ou")

	client, svcErr := s.provider.GetOAuthClientByClientID(ctx, "client-1")

	s.Nil(client)
	s.Require().NotNil(svcErr)
	s.Equal(tidcommon.ErrorUnauthorized.Code, svcErr.Code)
}

func (s *AccessingOUResolutionTestSuite) TestGrantLookupFailureIsAnInternalError() {
	s.expectClient()
	s.mockAccess.EXPECT().IsApplicationGrantedToOU(mock.Anything, "app-1", "other-ou").
		Return(false, &tidcommon.InternalServerError)
	ctx := syscontext.WithAccessingOUID(context.Background(), "other-ou")

	client, svcErr := s.provider.GetOAuthClientByClientID(ctx, "client-1")

	s.Nil(client)
	s.Require().NotNil(svcErr)
	s.Equal(tidcommon.InternalServerError.Code, svcErr.Code)
}

// With no grant resolver wired (a deployment without application management), a foreign
// organization unit must fail closed rather than resolve unchecked.
func (s *AccessingOUResolutionTestSuite) TestNoResolverConfiguredFailsClosed() {
	mockInbound := inboundclientmock.NewInboundClientServiceInterfaceMock(s.T())
	mockInbound.On("GetOAuthClientByClientID", mock.Anything, "client-1").
		Return(&providers.OAuthClient{ID: "app-1", ClientID: "client-1", OUID: "owner-ou"}, nil)
	provider := Initialize(
		mockInbound,
		entityprovidermock.NewEntityProviderInterfaceMock(s.T()),
		managermock.NewAuthnProviderManagerMock(s.T()),
		rolemock.NewRoleServiceInterfaceMock(s.T()),
		nil,
	)
	ctx := syscontext.WithAccessingOUID(context.Background(), "other-ou")

	client, svcErr := provider.GetOAuthClientByClientID(ctx, "client-1")

	s.Nil(client)
	s.Require().NotNil(svcErr)
	s.Equal(tidcommon.ErrorUnauthorized.Code, svcErr.Code)
}
