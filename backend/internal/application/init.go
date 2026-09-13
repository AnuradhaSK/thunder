// Copyright 2025 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

// Package application provides functionality for managing applications.
package application

import (
	"context"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/thunder-id/thunderid/internal/entity"
	"github.com/thunder-id/thunderid/internal/inboundclient"
	oupkg "github.com/thunder-id/thunderid/internal/ou"
	"github.com/thunder-id/thunderid/internal/serverconfig"
	"github.com/thunder-id/thunderid/internal/sharing"
	serverconst "github.com/thunder-id/thunderid/internal/system/constants"
	declarativeresource "github.com/thunder-id/thunderid/internal/system/declarative_resource"
	i18nmgt "github.com/thunder-id/thunderid/internal/system/i18n/mgt"
	"github.com/thunder-id/thunderid/internal/system/middleware"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

// Initialize initializes the application service and registers its routes.
func Initialize(
	mux *http.ServeMux,
	mcpServer *mcp.Server,
	entityService entity.EntityServiceInterface,
	inboundClient inboundclient.InboundClientServiceInterface,
	ouService oupkg.OrganizationUnitServiceInterface,
	i18nService i18nmgt.I18nServiceInterface,
	cryptoSvc providers.RuntimeCryptoProvider,
	serverConfigSvc serverconfig.ServerConfigService,
	artifactLifetime artifactLifetimeResolver,
	sharingService sharing.ServiceInterface,
) (ApplicationServiceInterface, declarativeresource.ResourceExporter, error) {
	appService := newApplicationService(
		inboundClient, entityService, ouService, i18nService, cryptoSvc, serverConfigSvc, artifactLifetime,
		sharingService,
	)

	// Onboard application onto the generic sharing framework so an application can be granted to
	// organization units other than its owner. Grants are declarative-only for now: there is no
	// REST surface for application sharing yet.
	if sharingService != nil {
		sharingService.RegisterResourceType(newApplicationTypeDeclaration())
	}

	if err := entityService.LoadIndexedAttributes(getAppIndexedAttributes()); err != nil {
		return nil, nil, err
	}

	storeMode := getApplicationStoreMode()
	// TODO: Revisit once the declarative resource loading pattern is finalized.
	if storeMode == serverconst.StoreModeComposite || storeMode == serverconst.StoreModeDeclarative {
		var pendingGrants []pendingAppGrant
		collect := func(p pendingAppGrant) { pendingGrants = append(pendingGrants, p) }
		if err := entityService.LoadDeclarativeResources(
			makeAppDeclarativeConfig(appService, collect)); err != nil {
			return nil, nil, err
		}
		// Replayed only after the whole batch has loaded, so a grant may name an organization unit
		// whose own declarative document is parsed later than the application's.
		if err := applyPendingAppGrants(pendingGrants, sharingService); err != nil {
			return nil, nil, err
		}
		if err := inboundClient.LoadDeclarativeResources(
			context.Background(), makeAppInboundConfig(appService)); err != nil {
			return nil, nil, err
		}
	}

	appHandler := newApplicationHandler(appService)
	registerRoutes(mux, appHandler)

	if mcpServer != nil {
		registerMCPTools(mcpServer, appService)
	}

	exporter := newApplicationExporter(appService)
	return appService, exporter, nil
}

func registerRoutes(mux *http.ServeMux, appHandler *applicationHandler) {
	opts1 := middleware.CORSOptions{
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   middleware.DefaultAllowedHeaders,
		AllowCredentials: true,
		MaxAge:           600,
	}
	mux.HandleFunc(middleware.WithCORS("POST /applications",
		appHandler.HandleApplicationPostRequest, opts1))
	mux.HandleFunc(middleware.WithCORS("GET /applications",
		appHandler.HandleApplicationListRequest, opts1))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /applications",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, opts1))

	opts2 := middleware.CORSOptions{
		AllowedMethods:   []string{"GET", "PUT", "DELETE"},
		AllowedHeaders:   middleware.DefaultAllowedHeaders,
		AllowCredentials: true,
		MaxAge:           600,
	}
	mux.HandleFunc(middleware.WithCORS("GET /applications/{id}",
		appHandler.HandleApplicationGetRequest, opts2))
	mux.HandleFunc(middleware.WithCORS("PUT /applications/{id}",
		appHandler.HandleApplicationPutRequest, opts2))
	mux.HandleFunc(middleware.WithCORS("DELETE /applications/{id}",
		appHandler.HandleApplicationDeleteRequest, opts2))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /applications/",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, opts2))
}
