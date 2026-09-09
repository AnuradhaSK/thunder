// Copyright 2025 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"fmt"
	"net/http"

	oupkg "github.com/thunder-id/thunderid/internal/ou"
	"github.com/thunder-id/thunderid/internal/sharing"
	serverconst "github.com/thunder-id/thunderid/internal/system/constants"
	declarativeresource "github.com/thunder-id/thunderid/internal/system/declarative_resource"
	"github.com/thunder-id/thunderid/internal/system/middleware"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

// Initialize initializes the resource service and registers its routes.
// Returns the service interface and resource server exporter for declarative resource export functionality.
func Initialize(
	mux *http.ServeMux,
	ouService oupkg.OrganizationUnitServiceInterface,
	sharingService sharing.ServiceInterface,
) (ResourceServiceInterface, declarativeresource.ResourceExporter, error) {
	// Initialize store and transactioner based on store mode
	resourceStore, transactioner, err := initializeStore()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize resource store: %w", err)
	}

	svc, err := newResourceService(ouService, resourceStore, transactioner, sharingService)
	if err != nil {
		return nil, nil, err
	}
	concreteSvc, ok := svc.(*resourceService)
	if !ok {
		return nil, nil, fmt.Errorf("internal error: resource service is not *resourceService")
	}

	// Load declarative resources if applicable (declarative or composite mode)
	storeMode := getResourceStoreMode()
	if storeMode == serverconst.StoreModeDeclarative || storeMode == serverconst.StoreModeComposite {
		if err := loadDeclarativeResources(resourceStore, svc); err != nil {
			return nil, nil, fmt.Errorf("failed to load declarative resources: %w", err)
		}
	}

	// Create exporter for declarative resource export functionality
	exporter := newResourceServerExporter(svc)

	resourceHandler := newResourceHandler(svc)
	registerRoutes(mux, resourceHandler)

	// Onboard resource servers, resources, and actions onto the generic sharing framework — one
	// resource type per tree level, so a specific action can be shared while a sibling is withheld.
	// The resource/action declarations hold
	// a reference to the concrete service so their SharingHooks.OnUnshare can resolve a node's
	// permission string and, once SetRolePermissionRevoker is wired in by servicemanager, strip it
	// from affected roles (§5.4).
	sharingService.RegisterResourceType(newResourceServerTypeDeclaration())
	sharingService.RegisterResourceType(newResourceNodeTypeDeclaration(concreteSvc))
	sharingService.RegisterResourceType(newActionTypeDeclaration(concreteSvc))

	return svc, exporter, nil
}

// initializeStore creates and initializes the appropriate store based on configuration.
func initializeStore() (resourceStoreInterface, providers.Transactioner, error) {
	storeMode := getResourceStoreMode()

	switch storeMode {
	case serverconst.StoreModeMutable:
		return newResourceStore()
	case serverconst.StoreModeDeclarative:
		return newFileBasedResourceStore()
	case serverconst.StoreModeComposite:
		fileStore, _, err := newFileBasedResourceStore()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create file-based store: %w", err)
		}
		dbStore, transactioner, err := newResourceStore()
		if err != nil {
			return nil, nil, err
		}
		return newCompositeResourceStore(fileStore, dbStore), transactioner, nil
	default:
		return nil, nil, fmt.Errorf("unsupported store mode: %s", storeMode)
	}
}

// registerRoutes registers all routes for the resource management API.
func registerRoutes(mux *http.ServeMux, handler *resourceHandler) {
	// Resource Server routes
	resourceServerOpts := middleware.CORSOptions{
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   middleware.DefaultAllowedHeaders,
		AllowCredentials: true,
		MaxAge:           600,
	}

	mux.HandleFunc(middleware.WithCORS("GET /resource-servers",
		handler.HandleResourceServerListRequest, resourceServerOpts))
	mux.HandleFunc(middleware.WithCORS("POST /resource-servers",
		handler.HandleResourceServerPostRequest, resourceServerOpts))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /resource-servers",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, resourceServerOpts))

	resourceServerDetailOpts := middleware.CORSOptions{
		AllowedMethods:   []string{"GET", "PUT", "DELETE"},
		AllowedHeaders:   middleware.DefaultAllowedHeaders,
		AllowCredentials: true,
		MaxAge:           600,
	}

	mux.HandleFunc(middleware.WithCORS("GET /resource-servers/{id}",
		handler.HandleResourceServerGetRequest, resourceServerDetailOpts))
	mux.HandleFunc(middleware.WithCORS("PUT /resource-servers/{id}",
		handler.HandleResourceServerPutRequest, resourceServerDetailOpts))
	mux.HandleFunc(middleware.WithCORS("DELETE /resource-servers/{id}",
		handler.HandleResourceServerDeleteRequest, resourceServerDetailOpts))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /resource-servers/{id}",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, resourceServerDetailOpts))

	// Resource routes
	resourceOpts := middleware.CORSOptions{
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   middleware.DefaultAllowedHeaders,
		AllowCredentials: true,
		MaxAge:           600,
	}

	mux.HandleFunc(middleware.WithCORS("GET /resource-servers/{rsId}/resources",
		handler.HandleResourceListRequest, resourceOpts))
	mux.HandleFunc(middleware.WithCORS("POST /resource-servers/{rsId}/resources",
		handler.HandleResourcePostRequest, resourceOpts))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /resource-servers/{rsId}/resources",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, resourceOpts))

	resourceDetailOpts := middleware.CORSOptions{
		AllowedMethods:   []string{"GET", "PUT", "DELETE"},
		AllowedHeaders:   middleware.DefaultAllowedHeaders,
		AllowCredentials: true,
		MaxAge:           600,
	}

	mux.HandleFunc(middleware.WithCORS("GET /resource-servers/{rsId}/resources/{id}",
		handler.HandleResourceGetRequest, resourceDetailOpts))
	mux.HandleFunc(middleware.WithCORS("PUT /resource-servers/{rsId}/resources/{id}",
		handler.HandleResourcePutRequest, resourceDetailOpts))
	mux.HandleFunc(middleware.WithCORS("DELETE /resource-servers/{rsId}/resources/{id}",
		handler.HandleResourceDeleteRequest, resourceDetailOpts))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /resource-servers/{rsId}/resources/{id}",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, resourceDetailOpts))

	// Action routes (Resource Server level)
	actionRSOpts := middleware.CORSOptions{
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   middleware.DefaultAllowedHeaders,
		AllowCredentials: true,
		MaxAge:           600,
	}

	mux.HandleFunc(middleware.WithCORS("GET /resource-servers/{rsId}/actions",
		handler.HandleActionListAtResourceServerRequest, actionRSOpts))
	mux.HandleFunc(middleware.WithCORS("POST /resource-servers/{rsId}/actions",
		handler.HandleActionPostAtResourceServerRequest, actionRSOpts))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /resource-servers/{rsId}/actions",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, actionRSOpts))

	actionRSDetailOpts := middleware.CORSOptions{
		AllowedMethods:   []string{"GET", "PUT", "DELETE"},
		AllowedHeaders:   middleware.DefaultAllowedHeaders,
		AllowCredentials: true,
		MaxAge:           600,
	}

	mux.HandleFunc(middleware.WithCORS("GET /resource-servers/{rsId}/actions/{id}",
		handler.HandleActionGetAtResourceServerRequest, actionRSDetailOpts))
	mux.HandleFunc(middleware.WithCORS("PUT /resource-servers/{rsId}/actions/{id}",
		handler.HandleActionPutAtResourceServerRequest, actionRSDetailOpts))
	mux.HandleFunc(middleware.WithCORS("DELETE /resource-servers/{rsId}/actions/{id}",
		handler.HandleActionDeleteAtResourceServerRequest, actionRSDetailOpts))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /resource-servers/{rsId}/actions/{id}",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, actionRSDetailOpts))

	// Action routes (Resource level)
	actionResourceOpts := middleware.CORSOptions{
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   middleware.DefaultAllowedHeaders,
		AllowCredentials: true,
		MaxAge:           600,
	}

	mux.HandleFunc(middleware.WithCORS("GET /resource-servers/{rsId}/resources/{resourceId}/actions",
		handler.HandleActionListAtResourceRequest, actionResourceOpts))
	mux.HandleFunc(middleware.WithCORS("POST /resource-servers/{rsId}/resources/{resourceId}/actions",
		handler.HandleActionPostAtResourceRequest, actionResourceOpts))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /resource-servers/{rsId}/resources/{resourceId}/actions",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, actionResourceOpts))

	actionResourceDetailOpts := middleware.CORSOptions{
		AllowedMethods:   []string{"GET", "PUT", "DELETE"},
		AllowedHeaders:   middleware.DefaultAllowedHeaders,
		AllowCredentials: true,
		MaxAge:           600,
	}

	mux.HandleFunc(middleware.WithCORS("GET /resource-servers/{rsId}/resources/{resourceId}/actions/{id}",
		handler.HandleActionGetAtResourceRequest, actionResourceDetailOpts))
	mux.HandleFunc(middleware.WithCORS("PUT /resource-servers/{rsId}/resources/{resourceId}/actions/{id}",
		handler.HandleActionPutAtResourceRequest, actionResourceDetailOpts))
	mux.HandleFunc(middleware.WithCORS("DELETE /resource-servers/{rsId}/resources/{resourceId}/actions/{id}",
		handler.HandleActionDeleteAtResourceRequest, actionResourceDetailOpts))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /resource-servers/{rsId}/resources/{resourceId}/actions/{id}",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, actionResourceDetailOpts))

	registerGrantRoutes(mux, handler)
}

// registerGrantRoutes registers the share-grant sub-resource routes for all three levels of
// the resource server/resource/action tree, mirroring the Role Management API's
// /roles/{id}/grants pattern.
func registerGrantRoutes(mux *http.ServeMux, handler *resourceHandler) {
	grantOpts := middleware.CORSOptions{
		AllowedMethods:   []string{"GET", "POST", "DELETE"},
		AllowedHeaders:   middleware.DefaultAllowedHeaders,
		AllowCredentials: true,
		MaxAge:           600,
	}
	optionsNoContent := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}

	// Resource server level.
	mux.HandleFunc(middleware.WithCORS("GET /resource-servers/{id}/grants",
		handler.HandleResourceServerGrantsGetRequest, grantOpts))
	mux.HandleFunc(middleware.WithCORS("POST /resource-servers/{id}/grants",
		handler.HandleResourceServerGrantsPostRequest, grantOpts))
	mux.HandleFunc(middleware.WithCORS("DELETE /resource-servers/{id}/grants/{grantId}",
		handler.HandleResourceServerUnshareRequest, grantOpts))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /resource-servers/{id}/grants", optionsNoContent, grantOpts))
	mux.HandleFunc(middleware.WithCORS(
		"OPTIONS /resource-servers/{id}/grants/{grantId}", optionsNoContent, grantOpts))

	// Resource level.
	mux.HandleFunc(middleware.WithCORS("GET /resource-servers/{rsId}/resources/{id}/grants",
		handler.HandleResourceGrantsGetRequest, grantOpts))
	mux.HandleFunc(middleware.WithCORS("POST /resource-servers/{rsId}/resources/{id}/grants",
		handler.HandleResourceGrantsPostRequest, grantOpts))
	mux.HandleFunc(middleware.WithCORS("DELETE /resource-servers/{rsId}/resources/{id}/grants/{grantId}",
		handler.HandleResourceUnshareRequest, grantOpts))
	mux.HandleFunc(middleware.WithCORS(
		"OPTIONS /resource-servers/{rsId}/resources/{id}/grants", optionsNoContent, grantOpts))
	mux.HandleFunc(middleware.WithCORS(
		"OPTIONS /resource-servers/{rsId}/resources/{id}/grants/{grantId}", optionsNoContent, grantOpts))

	// Action level — resource-server-level actions.
	mux.HandleFunc(middleware.WithCORS("GET /resource-servers/{rsId}/actions/{id}/grants",
		handler.HandleActionGrantsAtResourceServerGetRequest, grantOpts))
	mux.HandleFunc(middleware.WithCORS("POST /resource-servers/{rsId}/actions/{id}/grants",
		handler.HandleActionGrantsAtResourceServerPostRequest, grantOpts))
	mux.HandleFunc(middleware.WithCORS("DELETE /resource-servers/{rsId}/actions/{id}/grants/{grantId}",
		handler.HandleActionUnshareAtResourceServerRequest, grantOpts))
	mux.HandleFunc(middleware.WithCORS(
		"OPTIONS /resource-servers/{rsId}/actions/{id}/grants", optionsNoContent, grantOpts))
	mux.HandleFunc(middleware.WithCORS(
		"OPTIONS /resource-servers/{rsId}/actions/{id}/grants/{grantId}", optionsNoContent, grantOpts))

	// Action level — resource-nested actions.
	mux.HandleFunc(middleware.WithCORS(
		"GET /resource-servers/{rsId}/resources/{resourceId}/actions/{id}/grants",
		handler.HandleActionGrantsAtResourceGetRequest, grantOpts))
	mux.HandleFunc(middleware.WithCORS(
		"POST /resource-servers/{rsId}/resources/{resourceId}/actions/{id}/grants",
		handler.HandleActionGrantsAtResourcePostRequest, grantOpts))
	mux.HandleFunc(middleware.WithCORS(
		"DELETE /resource-servers/{rsId}/resources/{resourceId}/actions/{id}/grants/{grantId}",
		handler.HandleActionUnshareAtResourceRequest, grantOpts))
	mux.HandleFunc(middleware.WithCORS(
		"OPTIONS /resource-servers/{rsId}/resources/{resourceId}/actions/{id}/grants",
		optionsNoContent, grantOpts))
	mux.HandleFunc(middleware.WithCORS(
		"OPTIONS /resource-servers/{rsId}/resources/{resourceId}/actions/{id}/grants/{grantId}",
		optionsNoContent, grantOpts))
}
