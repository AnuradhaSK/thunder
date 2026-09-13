// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"

	"github.com/thunder-id/thunderid/internal/oauth/oauth2/constants"
	syscontext "github.com/thunder-id/thunderid/internal/system/context"
	"github.com/thunder-id/thunderid/tests/mocks/oumock"
)

// AccessingOUMiddlewareTestSuite covers the edge step that turns an /ou/{ouId} path prefix into a
// resolved organization unit on the request context, refusing the request when it names nothing.
type AccessingOUMiddlewareTestSuite struct {
	suite.Suite
	mockOU *oumock.OrganizationUnitServiceInterfaceMock
}

func TestAccessingOUMiddlewareTestSuite(t *testing.T) {
	suite.Run(t, new(AccessingOUMiddlewareTestSuite))
}

func (suite *AccessingOUMiddlewareTestSuite) SetupTest() {
	suite.mockOU = oumock.NewOrganizationUnitServiceInterfaceMock(suite.T())
}

// serve runs the middleware over a request for the given path, with ouID as its {ouId} path value
// when non-empty, and reports what the downstream handler saw.
func (suite *AccessingOUMiddlewareTestSuite) serve(
	path, ouID string,
) (status int, body string, reached bool, downstreamOUID string) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		downstreamOUID = syscontext.GetAccessingOUID(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, path, nil)
	if ouID != "" {
		req.SetPathValue(constants.PathParamOUID, ouID)
	}
	w := httptest.NewRecorder()

	accessingOUMiddleware(suite.mockOU)(handler).ServeHTTP(w, req)
	return w.Code, w.Body.String(), reached, downstreamOUID
}

// The bare endpoint has no prefix, so nothing is resolved and nothing is recorded; this is what
// keeps every pre-existing integration behaving exactly as before.
func (suite *AccessingOUMiddlewareTestSuite) TestNoPrefixPassesThroughUntouched() {
	status, _, reached, ouID := suite.serve("/oauth2/token", "")

	suite.Equal(http.StatusOK, status)
	suite.True(reached)
	suite.Empty(ouID)
	suite.mockOU.AssertNotCalled(suite.T(), "GetOrganizationUnit", mock.Anything, mock.Anything)
}

func (suite *AccessingOUMiddlewareTestSuite) TestResolvableOUIsRecordedOnTheContext() {
	suite.mockOU.EXPECT().GetOrganizationUnit(mock.Anything, "ou-1").
		Return(providers.OrganizationUnit{ID: "ou-1"}, nil)

	status, _, reached, ouID := suite.serve("/ou/ou-1/oauth2/token", "ou-1")

	suite.Equal(http.StatusOK, status)
	suite.True(reached)
	suite.Equal("ou-1", ouID)
}

// An id that names nothing must be refused here. It would otherwise satisfy a blanket all_ous
// grant, survive admission, and fail much later during claim resolution as a 500.
func (suite *AccessingOUMiddlewareTestSuite) TestUnresolvableOUIsRefusedBeforeTheHandler() {
	suite.mockOU.EXPECT().GetOrganizationUnit(mock.Anything, "nope").
		Return(providers.OrganizationUnit{}, &tidcommon.ErrorUnauthorized)

	status, body, reached, _ := suite.serve("/ou/nope/oauth2/token", "nope")

	suite.Equal(http.StatusBadRequest, status)
	suite.False(reached, "the request must not reach anything downstream")

	var resp map[string]string
	suite.Require().NoError(json.Unmarshal([]byte(body), &resp))
	// Identical to what an ungranted organization unit gets, so the two cannot be told apart and
	// the endpoint cannot be used to enumerate organization units.
	suite.Equal(constants.ErrorUnauthorizedClient, resp["error"])
}
