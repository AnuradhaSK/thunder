// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"net/http"

	sysutils "github.com/thunder-id/thunderid/internal/system/utils"
)

// decodeShareRequest decodes a POST .../grants body, matching the error handling convention
// used by every other write handler in this file.
func decodeShareRequest(r *http.Request) (ShareRequest, bool) {
	req, err := sysutils.DecodeJSONBody[ShareRequest](r)
	if err != nil {
		return ShareRequest{}, false
	}
	return *req, true
}

// toGrantListResponse converts service-layer grant info to its HTTP response shape.
func toGrantListResponse(grants []GrantInfo) *GrantListResponse {
	response := make([]GrantResponse, len(grants))
	for i, g := range grants {
		response[i] = GrantResponse(g)
	}
	return &GrantListResponse{Grants: response}
}

// Resource server share-grant handlers.

// HandleResourceServerGrantsPostRequest shares a resource server (cascading, by default, to
// every resource/action currently under it — see ShareRequest.ExcludedNodeIDs to withhold some).
func (h *resourceHandler) HandleResourceServerGrantsPostRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	req, ok := decodeShareRequest(r)
	if !ok {
		handleError(ctx, w, &ErrorInvalidRequestFormat)
		return
	}

	grants, svcErr := h.resourceService.ShareResourceServer(ctx, id, req)
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}
	sysutils.WriteSuccessResponse(ctx, w, http.StatusCreated, toGrantListResponse(grants))
}

// HandleResourceServerGrantsGetRequest lists a resource server's own grants.
func (h *resourceHandler) HandleResourceServerGrantsGetRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	grants, svcErr := h.resourceService.ListResourceServerGrants(ctx, id)
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}
	sysutils.WriteSuccessResponse(ctx, w, http.StatusOK, toGrantListResponse(grants))
}

// HandleResourceServerUnshareRequest revokes a resource server grant, cascading to every
// descendant grant created alongside it by the same cascade share.
func (h *resourceHandler) HandleResourceServerUnshareRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	grantID := r.PathValue("grantId")

	if svcErr := h.resourceService.UnshareResourceServerGrant(ctx, id, grantID); svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}
	sysutils.WriteSuccessResponse(ctx, w, http.StatusNoContent, nil)
}

// Resource share-grant handlers.

// HandleResourceGrantsPostRequest shares a resource (cascading to its sub-resources/actions).
func (h *resourceHandler) HandleResourceGrantsPostRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rsID := r.PathValue("rsId")
	id := r.PathValue("id")

	req, ok := decodeShareRequest(r)
	if !ok {
		handleError(ctx, w, &ErrorInvalidRequestFormat)
		return
	}

	grants, svcErr := h.resourceService.ShareResource(ctx, rsID, id, req)
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}
	sysutils.WriteSuccessResponse(ctx, w, http.StatusCreated, toGrantListResponse(grants))
}

// HandleResourceGrantsGetRequest lists a resource's own grants.
func (h *resourceHandler) HandleResourceGrantsGetRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rsID := r.PathValue("rsId")
	id := r.PathValue("id")

	grants, svcErr := h.resourceService.ListResourceGrants(ctx, rsID, id)
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}
	sysutils.WriteSuccessResponse(ctx, w, http.StatusOK, toGrantListResponse(grants))
}

// HandleResourceUnshareRequest revokes a resource grant, cascading to its descendants.
func (h *resourceHandler) HandleResourceUnshareRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rsID := r.PathValue("rsId")
	id := r.PathValue("id")
	grantID := r.PathValue("grantId")

	if svcErr := h.resourceService.UnshareResourceGrant(ctx, rsID, id, grantID); svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}
	sysutils.WriteSuccessResponse(ctx, w, http.StatusNoContent, nil)
}

// Action share-grant handlers — resource-server-level actions.

// HandleActionGrantsAtResourceServerPostRequest shares a resource-server-level action.
// Actions are leaves, so there is no cascade.
func (h *resourceHandler) HandleActionGrantsAtResourceServerPostRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rsID := r.PathValue("rsId")
	id := r.PathValue("id")

	req, ok := decodeShareRequest(r)
	if !ok {
		handleError(ctx, w, &ErrorInvalidRequestFormat)
		return
	}

	grants, svcErr := h.resourceService.ShareAction(ctx, rsID, nil, id, req)
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}
	sysutils.WriteSuccessResponse(ctx, w, http.StatusCreated, toGrantListResponse(grants))
}

// HandleActionGrantsAtResourceServerGetRequest lists a resource-server-level action's grants.
func (h *resourceHandler) HandleActionGrantsAtResourceServerGetRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rsID := r.PathValue("rsId")
	id := r.PathValue("id")

	grants, svcErr := h.resourceService.ListActionGrants(ctx, rsID, nil, id)
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}
	sysutils.WriteSuccessResponse(ctx, w, http.StatusOK, toGrantListResponse(grants))
}

// HandleActionUnshareAtResourceServerRequest revokes a resource-server-level action's grant.
func (h *resourceHandler) HandleActionUnshareAtResourceServerRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rsID := r.PathValue("rsId")
	id := r.PathValue("id")
	grantID := r.PathValue("grantId")

	if svcErr := h.resourceService.UnshareActionGrant(ctx, rsID, nil, id, grantID); svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}
	sysutils.WriteSuccessResponse(ctx, w, http.StatusNoContent, nil)
}

// Action share-grant handlers — resource-nested actions.

// HandleActionGrantsAtResourcePostRequest shares a resource-nested action.
func (h *resourceHandler) HandleActionGrantsAtResourcePostRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rsID := r.PathValue("rsId")
	resourceID := r.PathValue("resourceId")
	id := r.PathValue("id")

	req, ok := decodeShareRequest(r)
	if !ok {
		handleError(ctx, w, &ErrorInvalidRequestFormat)
		return
	}

	grants, svcErr := h.resourceService.ShareAction(ctx, rsID, &resourceID, id, req)
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}
	sysutils.WriteSuccessResponse(ctx, w, http.StatusCreated, toGrantListResponse(grants))
}

// HandleActionGrantsAtResourceGetRequest lists a resource-nested action's grants.
func (h *resourceHandler) HandleActionGrantsAtResourceGetRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rsID := r.PathValue("rsId")
	resourceID := r.PathValue("resourceId")
	id := r.PathValue("id")

	grants, svcErr := h.resourceService.ListActionGrants(ctx, rsID, &resourceID, id)
	if svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}
	sysutils.WriteSuccessResponse(ctx, w, http.StatusOK, toGrantListResponse(grants))
}

// HandleActionUnshareAtResourceRequest revokes a resource-nested action's grant.
func (h *resourceHandler) HandleActionUnshareAtResourceRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rsID := r.PathValue("rsId")
	resourceID := r.PathValue("resourceId")
	id := r.PathValue("id")
	grantID := r.PathValue("grantId")

	if svcErr := h.resourceService.UnshareActionGrant(ctx, rsID, &resourceID, id, grantID); svcErr != nil {
		handleError(ctx, w, svcErr)
		return
	}
	sysutils.WriteSuccessResponse(ctx, w, http.StatusNoContent, nil)
}
