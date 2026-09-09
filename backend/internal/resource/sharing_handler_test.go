// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/sharing"
)

// SharingHandlerTestSuite covers the HTTP handlers in sharing_handler.go: share/list/unshare for
// resource servers, resources, and both action variants (resource-server-level and
// resource-nested).
type SharingHandlerTestSuite struct {
	suite.Suite
	mockService *ResourceServiceInterfaceMock
	handler     *resourceHandler
}

func TestSharingHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(SharingHandlerTestSuite))
}

func (suite *SharingHandlerTestSuite) SetupTest() {
	suite.mockService = new(ResourceServiceInterfaceMock)
	suite.handler = newResourceHandler(suite.mockService)
}

var sampleGrants = []GrantInfo{
	{
		ID: "grant-1", NodeType: "resource_server", NodeID: "rs-123",
		Stage: "share", TargetScope: "all_children", TargetOUID: "ou-1", OwningOUID: "owner-ou",
	},
}

// testSharedResourceID is a fixture resource ID reused across the resource/action share-grant
// handler tests in this file.
const testSharedResourceID = "resource-1"

// --- Resource server share-grant handlers ---

func (suite *SharingHandlerTestSuite) TestHandleResourceServerGrantsPostRequest_Success() {
	suite.mockService.On("ShareResourceServer", mock.Anything, "rs-123",
		mock.MatchedBy(func(req ShareRequest) bool { return req.AllChildren })).
		Return(sampleGrants, nil)

	body, _ := json.Marshal(ShareRequest{AllChildren: true})
	req := httptest.NewRequest("POST", "/resource-servers/rs-123/grants", bytes.NewReader(body))
	req.SetPathValue("id", "rs-123")
	w := httptest.NewRecorder()

	suite.handler.HandleResourceServerGrantsPostRequest(w, req)

	suite.Equal(http.StatusCreated, w.Code)
	var resp GrantListResponse
	suite.NoError(json.Unmarshal(w.Body.Bytes(), &resp))
	suite.Len(resp.Grants, 1)
	suite.Equal("grant-1", resp.Grants[0].ID)
}

func (suite *SharingHandlerTestSuite) TestHandleResourceServerGrantsPostRequest_InvalidJSON() {
	req := httptest.NewRequest("POST", "/resource-servers/rs-123/grants", bytes.NewReader([]byte("not json")))
	req.SetPathValue("id", "rs-123")
	w := httptest.NewRecorder()

	suite.handler.HandleResourceServerGrantsPostRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

func (suite *SharingHandlerTestSuite) TestHandleResourceServerGrantsPostRequest_ServiceError() {
	suite.mockService.On("ShareResourceServer", mock.Anything, "rs-123", mock.Anything).
		Return(nil, &ErrorResourceServerNotFound)

	body, _ := json.Marshal(ShareRequest{AllChildren: true})
	req := httptest.NewRequest("POST", "/resource-servers/rs-123/grants", bytes.NewReader(body))
	req.SetPathValue("id", "rs-123")
	w := httptest.NewRecorder()

	suite.handler.HandleResourceServerGrantsPostRequest(w, req)

	suite.Equal(http.StatusNotFound, w.Code)
}

func (suite *SharingHandlerTestSuite) TestHandleResourceServerGrantsGetRequest_Success() {
	suite.mockService.On("ListResourceServerGrants", mock.Anything, "rs-123").
		Return(sampleGrants, nil)

	req := httptest.NewRequest("GET", "/resource-servers/rs-123/grants", nil)
	req.SetPathValue("id", "rs-123")
	w := httptest.NewRecorder()

	suite.handler.HandleResourceServerGrantsGetRequest(w, req)

	suite.Equal(http.StatusOK, w.Code)
	var resp GrantListResponse
	suite.NoError(json.Unmarshal(w.Body.Bytes(), &resp))
	suite.Len(resp.Grants, 1)
}

func (suite *SharingHandlerTestSuite) TestHandleResourceServerGrantsGetRequest_ServiceError() {
	suite.mockService.On("ListResourceServerGrants", mock.Anything, "rs-123").
		Return(nil, &tidcommon.InternalServerError)

	req := httptest.NewRequest("GET", "/resource-servers/rs-123/grants", nil)
	req.SetPathValue("id", "rs-123")
	w := httptest.NewRecorder()

	suite.handler.HandleResourceServerGrantsGetRequest(w, req)

	suite.Equal(http.StatusInternalServerError, w.Code)
}

func (suite *SharingHandlerTestSuite) TestHandleResourceServerUnshareRequest_Success() {
	suite.mockService.On("UnshareResourceServerGrant", mock.Anything, "rs-123", "grant-1").Return(nil)

	req := httptest.NewRequest("DELETE", "/resource-servers/rs-123/grants/grant-1", nil)
	req.SetPathValue("id", "rs-123")
	req.SetPathValue("grantId", "grant-1")
	w := httptest.NewRecorder()

	suite.handler.HandleResourceServerUnshareRequest(w, req)

	suite.Equal(http.StatusNoContent, w.Code)
}

func (suite *SharingHandlerTestSuite) TestHandleResourceServerUnshareRequest_GrantNotFound() {
	suite.mockService.On("UnshareResourceServerGrant", mock.Anything, "rs-123", "missing").
		Return(&sharing.ErrorGrantNotFound)

	req := httptest.NewRequest("DELETE", "/resource-servers/rs-123/grants/missing", nil)
	req.SetPathValue("id", "rs-123")
	req.SetPathValue("grantId", "missing")
	w := httptest.NewRecorder()

	suite.handler.HandleResourceServerUnshareRequest(w, req)

	suite.Equal(http.StatusNotFound, w.Code)
}

// --- Resource share-grant handlers ---

func (suite *SharingHandlerTestSuite) TestHandleResourceGrantsPostRequest_Success() {
	suite.mockService.On("ShareResource", mock.Anything, "rs-123", testSharedResourceID, mock.Anything).
		Return(sampleGrants, nil)

	body, _ := json.Marshal(ShareRequest{AllChildren: true})
	req := httptest.NewRequest("POST", "/resource-servers/rs-123/resources/res-1/grants", bytes.NewReader(body))
	req.SetPathValue("rsId", "rs-123")
	req.SetPathValue("id", testSharedResourceID)
	w := httptest.NewRecorder()

	suite.handler.HandleResourceGrantsPostRequest(w, req)

	suite.Equal(http.StatusCreated, w.Code)
}

func (suite *SharingHandlerTestSuite) TestHandleResourceGrantsGetRequest_Success() {
	suite.mockService.On("ListResourceGrants", mock.Anything, "rs-123", testSharedResourceID).
		Return(sampleGrants, nil)

	req := httptest.NewRequest("GET", "/resource-servers/rs-123/resources/res-1/grants", nil)
	req.SetPathValue("rsId", "rs-123")
	req.SetPathValue("id", testSharedResourceID)
	w := httptest.NewRecorder()

	suite.handler.HandleResourceGrantsGetRequest(w, req)

	suite.Equal(http.StatusOK, w.Code)
}

func (suite *SharingHandlerTestSuite) TestHandleResourceUnshareRequest_Success() {
	suite.mockService.On("UnshareResourceGrant", mock.Anything, "rs-123", testSharedResourceID, "grant-1").Return(nil)

	req := httptest.NewRequest("DELETE", "/resource-servers/rs-123/resources/res-1/grants/grant-1", nil)
	req.SetPathValue("rsId", "rs-123")
	req.SetPathValue("id", testSharedResourceID)
	req.SetPathValue("grantId", "grant-1")
	w := httptest.NewRecorder()

	suite.handler.HandleResourceUnshareRequest(w, req)

	suite.Equal(http.StatusNoContent, w.Code)
}

// --- Action share-grant handlers: resource-server level ---

func (suite *SharingHandlerTestSuite) TestHandleActionGrantsAtResourceServerPostRequest_Success() {
	suite.mockService.On("ShareAction", mock.Anything, "rs-123", (*string)(nil), "act-1", mock.Anything).
		Return(sampleGrants, nil)

	body, _ := json.Marshal(ShareRequest{AllChildren: true})
	req := httptest.NewRequest("POST", "/resource-servers/rs-123/actions/act-1/grants", bytes.NewReader(body))
	req.SetPathValue("rsId", "rs-123")
	req.SetPathValue("id", "act-1")
	w := httptest.NewRecorder()

	suite.handler.HandleActionGrantsAtResourceServerPostRequest(w, req)

	suite.Equal(http.StatusCreated, w.Code)
}

func (suite *SharingHandlerTestSuite) TestHandleActionGrantsAtResourceServerGetRequest_Success() {
	suite.mockService.On("ListActionGrants", mock.Anything, "rs-123", (*string)(nil), "act-1").
		Return(sampleGrants, nil)

	req := httptest.NewRequest("GET", "/resource-servers/rs-123/actions/act-1/grants", nil)
	req.SetPathValue("rsId", "rs-123")
	req.SetPathValue("id", "act-1")
	w := httptest.NewRecorder()

	suite.handler.HandleActionGrantsAtResourceServerGetRequest(w, req)

	suite.Equal(http.StatusOK, w.Code)
}

func (suite *SharingHandlerTestSuite) TestHandleActionUnshareAtResourceServerRequest_Success() {
	suite.mockService.On("UnshareActionGrant", mock.Anything, "rs-123", (*string)(nil), "act-1", "grant-1").
		Return(nil)

	req := httptest.NewRequest("DELETE", "/resource-servers/rs-123/actions/act-1/grants/grant-1", nil)
	req.SetPathValue("rsId", "rs-123")
	req.SetPathValue("id", "act-1")
	req.SetPathValue("grantId", "grant-1")
	w := httptest.NewRecorder()

	suite.handler.HandleActionUnshareAtResourceServerRequest(w, req)

	suite.Equal(http.StatusNoContent, w.Code)
}

// --- Action share-grant handlers: resource-nested ---

func (suite *SharingHandlerTestSuite) TestHandleActionGrantsAtResourcePostRequest_Success() {
	suite.mockService.On("ShareAction", mock.Anything, "rs-123",
		mock.MatchedBy(func(resID *string) bool { return resID != nil && *resID == testSharedResourceID }),
		"act-1", mock.Anything).
		Return(sampleGrants, nil)

	body, _ := json.Marshal(ShareRequest{AllChildren: true})
	req := httptest.NewRequest(
		"POST", "/resource-servers/rs-123/resources/res-1/actions/act-1/grants", bytes.NewReader(body),
	)
	req.SetPathValue("rsId", "rs-123")
	req.SetPathValue("resourceId", testSharedResourceID)
	req.SetPathValue("id", "act-1")
	w := httptest.NewRecorder()

	suite.handler.HandleActionGrantsAtResourcePostRequest(w, req)

	suite.Equal(http.StatusCreated, w.Code)
}

func (suite *SharingHandlerTestSuite) TestHandleActionGrantsAtResourceGetRequest_Success() {
	suite.mockService.On("ListActionGrants", mock.Anything, "rs-123",
		mock.MatchedBy(func(resID *string) bool { return resID != nil && *resID == testSharedResourceID }),
		"act-1").
		Return(sampleGrants, nil)

	req := httptest.NewRequest("GET", "/resource-servers/rs-123/resources/res-1/actions/act-1/grants", nil)
	req.SetPathValue("rsId", "rs-123")
	req.SetPathValue("resourceId", testSharedResourceID)
	req.SetPathValue("id", "act-1")
	w := httptest.NewRecorder()

	suite.handler.HandleActionGrantsAtResourceGetRequest(w, req)

	suite.Equal(http.StatusOK, w.Code)
}

func (suite *SharingHandlerTestSuite) TestHandleActionUnshareAtResourceRequest_Success() {
	suite.mockService.On("UnshareActionGrant", mock.Anything, "rs-123",
		mock.MatchedBy(func(resID *string) bool { return resID != nil && *resID == testSharedResourceID }),
		"act-1", "grant-1").
		Return(nil)

	req := httptest.NewRequest(
		"DELETE", "/resource-servers/rs-123/resources/res-1/actions/act-1/grants/grant-1", nil,
	)
	req.SetPathValue("rsId", "rs-123")
	req.SetPathValue("resourceId", testSharedResourceID)
	req.SetPathValue("id", "act-1")
	req.SetPathValue("grantId", "grant-1")
	w := httptest.NewRecorder()

	suite.handler.HandleActionUnshareAtResourceRequest(w, req)

	suite.Equal(http.StatusNoContent, w.Code)
}
