// Copyright 2025 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package granthandlers

import (
	"context"
	"slices"

	"github.com/thunder-id/thunderid/internal/oauth/oauth2/constants"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/dpop"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/model"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/resourceindicators"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/tokenservice"
	"github.com/thunder-id/thunderid/internal/system/log"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

// clientCredentialsGrantHandler handles the client credentials grant type.
type clientCredentialsGrantHandler struct {
	tokenBuilder    tokenservice.TokenBuilderInterface
	ouService       providers.OrganizationUnitProvider
	authzService    providers.AuthorizationProvider
	actorProvider   providers.ActorProvider
	resourceService providers.ResourceServerProvider
	appGrantService providers.ApplicationOUAccessProvider
}

// newClientCredentialsGrantHandler creates a new instance of ClientCredentialsGrantHandler.
func newClientCredentialsGrantHandler(
	tokenBuilder tokenservice.TokenBuilderInterface,
	ouService providers.OrganizationUnitProvider,
	authzService providers.AuthorizationProvider,
	actorProvider providers.ActorProvider,
	resourceService providers.ResourceServerProvider,
	appGrantService providers.ApplicationOUAccessProvider,
) GrantHandlerInterface {
	return &clientCredentialsGrantHandler{
		tokenBuilder:    tokenBuilder,
		ouService:       ouService,
		authzService:    authzService,
		actorProvider:   actorProvider,
		resourceService: resourceService,
		appGrantService: appGrantService,
	}
}

// ValidateGrant validates the client credentials grant type.
func (h *clientCredentialsGrantHandler) ValidateGrant(ctx context.Context, tokenRequest *model.TokenRequest,
	oauthApp *providers.OAuthClient) *model.ErrorResponse {
	if providers.GrantType(tokenRequest.GrantType) != providers.GrantTypeClientCredentials {
		return &model.ErrorResponse{
			Error:            constants.ErrorUnsupportedGrantType,
			ErrorDescription: "Unsupported grant type",
		}
	}

	if errResp := resourceindicators.ValidateResourceURIs(tokenRequest.Resources); errResp != nil {
		return errResp
	}

	if errResp := h.validateAccessingOU(ctx, tokenRequest, oauthApp); errResp != nil {
		return errResp
	}

	return nil
}

// validateAccessingOU rejects the request unless the application may be used against the
// organization unit named on the /ou/{ouId} path. A request that named none is always allowed,
// which is what keeps the bare /oauth2/token endpoint behaving exactly as before.
//
// The failure is unauthorized_client, matching how the token service already reports a client that
// may not use a given grant type. The client authenticated successfully; it simply has no grant for
// the organization unit it asked for, so invalid_client would misdescribe it.
func (h *clientCredentialsGrantHandler) validateAccessingOU(
	ctx context.Context, tokenRequest *model.TokenRequest, oauthApp *providers.OAuthClient,
) *model.ErrorResponse {
	if tokenRequest.AccessingOUID == "" {
		return nil
	}
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "ClientCredentialsGrantHandler"))

	// Resolve the named organization unit before anything else. Without this an id that names
	// nothing would reach the grant check, where an allOus grant blanket-matches it, and then fail
	// deeper in claim resolution as a 500. It is refused the same way an ungranted one is.
	if h.ouService != nil {
		if _, svcErr := h.ouService.GetOrganizationUnit(ctx, tokenRequest.AccessingOUID); svcErr != nil {
			logger.Debug(ctx, "Token requested against an unresolvable organization unit",
				log.String("ouID", tokenRequest.AccessingOUID))
			return &model.ErrorResponse{
				Error:            constants.ErrorUnauthorizedClient,
				ErrorDescription: "The client is not authorized for the requested organization unit",
			}
		}
	}

	// The owning organization unit may always name itself; it needs no grant of its own.
	if oauthApp != nil && oauthApp.OUID == tokenRequest.AccessingOUID {
		return nil
	}

	if h.appGrantService == nil || oauthApp == nil {
		logger.Error(ctx, "Cannot resolve application grants for an OU-scoped token request",
			log.String("ouID", tokenRequest.AccessingOUID))
		return &model.ErrorResponse{
			Error:            constants.ErrorServerError,
			ErrorDescription: "Failed to generate token",
		}
	}

	granted, svcErr := h.appGrantService.IsApplicationGrantedToOU(ctx, oauthApp.ID, tokenRequest.AccessingOUID)
	if svcErr != nil {
		logger.Error(ctx, "Failed to resolve application grant for organization unit",
			log.String("appID", oauthApp.ID), log.String("ouID", tokenRequest.AccessingOUID),
			log.String("error", svcErr.Error.DefaultValue))
		return &model.ErrorResponse{
			Error:            constants.ErrorServerError,
			ErrorDescription: "Failed to generate token",
		}
	}
	if !granted {
		logger.Debug(ctx, "Application is not granted to the requested organization unit",
			log.String("appID", oauthApp.ID), log.String("ouID", tokenRequest.AccessingOUID))
		return &model.ErrorResponse{
			Error:            constants.ErrorUnauthorizedClient,
			ErrorDescription: "The client is not authorized for the requested organization unit",
		}
	}
	return nil
}

// HandleGrant handles the client credentials grant type.
func (h *clientCredentialsGrantHandler) HandleGrant(ctx context.Context, tokenRequest *model.TokenRequest,
	oauthApp *providers.OAuthClient) (
	*model.TokenResponseDTO, *model.ErrorResponse) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "ClientCredentialsGrantHandler"))

	scopes := tokenservice.ParseScopes(tokenRequest.Scope)

	// A client_credentials token carries no OIDC scopes, so every requested scope is a permission
	// scope. Bind the token to a single resource server (RFC 8707 resource or the configured
	// default). A request with neither scopes nor a resource is not bound to a resource server: its
	// audience is the app's configured default audiences (falling back to the client_id) and it
	// carries no scopes.
	targetRS, errResp := resourceindicators.ResolveAudienceBinding(
		ctx, h.resourceService, tokenRequest.Resources, scopes)
	if errResp != nil {
		return nil, errResp
	}

	audiences := []string{oauthApp.ResolveDefaultAudience(tokenRequest.ClientID)}
	if targetRS != nil {
		audiences = []string{targetRS.Identifier}

		// Downscope requested scopes to permissions defined on the target resource server. When the
		// request named an accessing organization unit, this also drops the permissions that
		// organization unit was never granted, so a token can never carry more than it can see.
		scopes, errResp = resourceindicators.DownscopeToResourceServer(
			ctx, h.resourceService, targetRS.ID, scopes, tokenRequest.AccessingOUID)
		if errResp != nil {
			return nil, errResp
		}

		if len(scopes) > 0 {
			var groupIDs []string
			if h.actorProvider != nil {
				groups, groupErr := h.actorProvider.GetActorGroups(oauthApp.ID)
				if groupErr != nil {
					logger.Error(ctx, "Failed to resolve app group memberships",
						log.String("appID", oauthApp.ID), log.String("error", groupErr.Error.DefaultValue))
					return nil, &model.ErrorResponse{
						Error:            constants.ErrorServerError,
						ErrorDescription: "Failed to generate token",
					}
				} else {
					for _, group := range groups {
						if group.ID != "" && !slices.Contains(groupIDs, group.ID) {
							groupIDs = append(groupIDs, group.ID)
						}
					}
				}
			}

			authzResp, svcErr := h.authzService.EvaluateAccessBatch(ctx,
				buildAccessEvaluationsRequest(oauthApp.ID, groupIDs, scopes, targetRS.ID, oauthApp.OUID))
			if svcErr != nil {
				logger.Error(ctx, "Failed to get authorized permissions for app",
					log.String("appID", oauthApp.ID), log.String("error", svcErr.Error.DefaultValue))
				return nil, &model.ErrorResponse{
					Error:            constants.ErrorServerError,
					ErrorDescription: "Failed to generate token",
				}
			}

			// The evaluation above answers "what is this application entitled to", resolved from
			// its own owning OU via its direct role assignments and group memberships. That answer
			// is independent of who the token is for; the accessing organization unit has already
			// had its say during downscoping, and can only narrow this further.
			scopes = filterAuthorizedScopes(scopes, authzResp.Evaluations)
		}
	}

	clientAttributes, clientAttrErr := tokenservice.BuildClientAttributes(
		ctx, oauthApp, h.ouService, h.actorProvider, tokenRequest.AccessingOUID)
	if clientAttrErr != nil {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorServerError,
			ErrorDescription: "Failed to generate token",
		}
	}

	accessToken, err := h.tokenBuilder.BuildAccessToken(ctx, &tokenservice.AccessTokenBuildContext{
		Subject:           oauthApp.ID,
		Audiences:         audiences,
		ClientID:          tokenRequest.ClientID,
		Scopes:            scopes,
		SubjectAttributes: clientAttributes,
		GrantType:         string(providers.GrantTypeClientCredentials),
		OAuthApp:          oauthApp,
		ValidityPeriod:    oauthApp.ClientAccessTokenConfig().ValidityPeriodOrZero(),
		DPoPJkt:           dpop.GetJkt(ctx),
	})
	if err != nil {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorServerError,
			ErrorDescription: "Failed to generate token",
		}
	}

	return &model.TokenResponseDTO{
		AccessToken: *accessToken,
	}, nil
}

func buildAccessEvaluationsRequest(
	entityID string,
	groupIDs []string,
	permissions []string,
	resourceServerID string,
	ouID string,
) providers.AccessEvaluationsRequest {
	evaluations := make([]providers.AccessEvaluationRequest, 0, len(permissions))
	for _, permission := range permissions {
		evaluations = append(evaluations, providers.AccessEvaluationRequest{
			Subject: providers.Subject{
				ID:       entityID,
				GroupIDs: groupIDs,
			},
			ResourceServer: providers.AccessEvaluationResourceServer{ID: resourceServerID},
			Permission:     providers.Permission{Name: permission},
			OUID:           ouID,
		})
	}
	return providers.AccessEvaluationsRequest{Evaluations: evaluations}
}

func filterAuthorizedScopes(scopes []string, evaluations []providers.AccessEvaluationResponse) []string {
	authorizedScopes := make([]string, 0, len(evaluations))
	for i, evaluation := range evaluations {
		if evaluation.Decision && i < len(scopes) {
			authorizedScopes = append(authorizedScopes, scopes[i])
		}
	}
	return authorizedScopes
}
