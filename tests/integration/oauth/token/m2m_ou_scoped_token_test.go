// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/thunder-id/thunderid/tests/integration/testutils"
)

// M2MOUScopedTokenTestSuite covers the accessing-organization-unit form of the token endpoint,
// /ou/{ouId}/oauth2/token, against the declaratively defined M2M service applications in
// resources/declarative_resources/applications/m2m-declarative-apps.yaml.
//
// The applications are owned by decl-m2m-root and granted outward three different ways (every OU in
// the deployment, the owning subtree, and one named child), which is what lets a single credential
// pair serve many organizations while remaining invisible inside them.
type M2MOUScopedTokenTestSuite struct {
	suite.Suite
}

func TestM2MOUScopedTokenTestSuite(t *testing.T) {
	suite.Run(t, new(M2MOUScopedTokenTestSuite))
}

const (
	m2mRootOUID   = "decl-m2m-root"
	m2mChildAOUID = "decl-m2m-child-a"
	m2mChildBOUID = "decl-m2m-child-b"

	m2mAllOUsClientID     = "decl-m2m-all-ous-client"
	m2mAllOUsSecret       = "decl-m2m-all-ous-secret"
	m2mSubtreeClientID    = "decl-m2m-subtree-client"
	m2mSubtreeSecret      = "decl-m2m-subtree-secret"
	m2mSubtreeAppID       = "decl-m2m-subtree"
	m2mSelectiveClientID  = "decl-m2m-selective-client"
	m2mSelectiveSecret    = "decl-m2m-selective-secret"
	unrelatedDeclOUHandle = "decl-ou-1"
)

// requestToken issues a client_credentials request. When ouID is non-empty the request goes to the
// /ou/{ouId} form of the endpoint, otherwise to the bare one.
func (suite *M2MOUScopedTokenTestSuite) requestToken(
	ouID, clientID, clientSecret string,
) (int, map[string]interface{}) {
	suite.T().Helper()

	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	endpoint := testutils.TestServerURL + "/oauth2/token"
	if ouID != "" {
		endpoint = testutils.TestServerURL + "/ou/" + ouID + "/oauth2/token"
	}

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(form.Encode()))
	suite.Require().NoError(err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	// Raw client: this test sets its own Authorization header (client_secret_basic), so the
	// harness must not inject an admin bearer over it.
	resp, err := testutils.GetRawHTTPClient().Do(req)
	suite.Require().NoError(err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err)

	parsed := map[string]interface{}{}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &parsed)
	}
	return resp.StatusCode, parsed
}

// TestBareEndpointStillWorks pins the backwards-compatibility guarantee: a request that does not
// name an accessing organization unit behaves exactly as it did before the prefix existed, with no
// grant required.
func (suite *M2MOUScopedTokenTestSuite) TestBareEndpointStillWorks() {
	status, body := suite.requestToken("", m2mSelectiveClientID, m2mSelectiveSecret)

	suite.Equal(http.StatusOK, status, "body: %v", body)
	suite.NotEmpty(body["access_token"])
}

// TestAllOUsGrantReachesEveryOU proves an allOus grant lets the application be used against any
// organization unit, including ones in an unrelated tree.
func (suite *M2MOUScopedTokenTestSuite) TestAllOUsGrantReachesEveryOU() {
	for _, ouID := range []string{m2mRootOUID, m2mChildAOUID, m2mChildBOUID, unrelatedDeclOUHandle} {
		suite.Run(ouID, func() {
			status, body := suite.requestToken(ouID, m2mAllOUsClientID, m2mAllOUsSecret)

			suite.Equal(http.StatusOK, status, "body: %v", body)
			suite.NotEmpty(body["access_token"])
		})
	}
}

// TestOwnerMayAlwaysNameItself proves the owning organization unit needs no grant of its own.
func (suite *M2MOUScopedTokenTestSuite) TestOwnerMayAlwaysNameItself() {
	status, body := suite.requestToken(m2mRootOUID, m2mSelectiveClientID, m2mSelectiveSecret)

	suite.Equal(http.StatusOK, status, "body: %v", body)
	suite.NotEmpty(body["access_token"])
}

// TestSubtreeGrantCoversChildren proves an allChildren grant reaches the owning root's descendants.
func (suite *M2MOUScopedTokenTestSuite) TestSubtreeGrantCoversChildren() {
	for _, ouID := range []string{m2mChildAOUID, m2mChildBOUID} {
		suite.Run(ouID, func() {
			status, body := suite.requestToken(ouID, m2mSubtreeClientID, m2mSubtreeSecret)

			suite.Equal(http.StatusOK, status, "body: %v", body)
			suite.NotEmpty(body["access_token"])
		})
	}
}

// TestSubtreeGrantDoesNotReachAnotherTree proves allChildren stays inside the owning subtree.
func (suite *M2MOUScopedTokenTestSuite) TestSubtreeGrantDoesNotReachAnotherTree() {
	status, body := suite.requestToken(unrelatedDeclOUHandle, m2mSubtreeClientID, m2mSubtreeSecret)

	suite.Equal(http.StatusBadRequest, status, "body: %v", body)
	suite.Equal("unauthorized_client", body["error"])
}

// TestSelectiveGrantExcludesUngrantedSibling is the case the selective grant exists to express:
// child A was named, child B was not, and B must be refused even though it sits in the same subtree.
func (suite *M2MOUScopedTokenTestSuite) TestSelectiveGrantExcludesUngrantedSibling() {
	grantedStatus, grantedBody := suite.requestToken(m2mChildAOUID, m2mSelectiveClientID, m2mSelectiveSecret)
	suite.Equal(http.StatusOK, grantedStatus, "body: %v", grantedBody)
	suite.NotEmpty(grantedBody["access_token"])

	refusedStatus, refusedBody := suite.requestToken(m2mChildBOUID, m2mSelectiveClientID, m2mSelectiveSecret)
	suite.Equal(http.StatusBadRequest, refusedStatus, "body: %v", refusedBody)
	suite.Equal("unauthorized_client", refusedBody["error"])
}

// TestUnknownOUIsRefused proves an organization unit id that resolves to nothing is refused, for a
// blanket allOus grant just as much as for a selective one. allOus means "every organization unit in
// the deployment", and a grant check alone cannot reject an id that names none of them, so the
// accessing organization unit is resolved before the grant is consulted.
func (suite *M2MOUScopedTokenTestSuite) TestUnknownOUIsRefused() {
	for _, tc := range []struct{ name, clientID, secret string }{
		{"selective grant", m2mSelectiveClientID, m2mSelectiveSecret},
		{"allOus grant", m2mAllOUsClientID, m2mAllOUsSecret},
	} {
		suite.Run(tc.name, func() {
			status, body := suite.requestToken("no-such-ou", tc.clientID, tc.secret)

			suite.Equal(http.StatusBadRequest, status, "body: %v", body)
			suite.Equal("unauthorized_client", body["error"])
		})
	}
}

// decodeAccessTokenClaims returns the JWT payload claims of an issued access token.
func (suite *M2MOUScopedTokenTestSuite) decodeAccessTokenClaims(body map[string]interface{}) map[string]interface{} {
	suite.T().Helper()

	token, ok := body["access_token"].(string)
	suite.Require().True(ok, "no access_token in body: %v", body)
	parts := strings.Split(token, ".")
	suite.Require().Len(parts, 3, "access token is not a JWS")

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	suite.Require().NoError(err)
	claims := map[string]interface{}{}
	suite.Require().NoError(json.Unmarshal(payload, &claims))
	return claims
}

// TestClaimsNameTheAccessingOU proves the token states which organization it was issued for: on an
// /ou/{ouId} request the ouId/ouHandle claims resolve to the accessing organization unit, not to the
// application's own owner. Without the prefix they fall back to the owner, unchanged.
func (suite *M2MOUScopedTokenTestSuite) TestClaimsNameTheAccessingOU() {
	_, accessing := suite.requestToken(m2mChildAOUID, m2mAllOUsClientID, m2mAllOUsSecret)
	accessingClaims := suite.decodeAccessTokenClaims(accessing)
	suite.Equal(m2mChildAOUID, accessingClaims["ouId"],
		"the token must name the organization it was requested against")
	suite.Equal(m2mChildAOUID, accessingClaims["ouHandle"])

	_, bare := suite.requestToken("", m2mAllOUsClientID, m2mAllOUsSecret)
	bareClaims := suite.decodeAccessTokenClaims(bare)
	suite.Equal(m2mRootOUID, bareClaims["ouId"],
		"without an accessing organization unit the claims stay with the application's owner")
}

// TestWrongSecretFailsAsInvalidClient proves client authentication runs before any organization unit
// logic: a bad secret is refused as invalid_client regardless of how broadly the application is
// granted, and is distinguishable from the unauthorized_client an ungranted organization unit gets.
func (suite *M2MOUScopedTokenTestSuite) TestWrongSecretFailsAsInvalidClient() {
	status, body := suite.requestToken(m2mChildAOUID, m2mAllOUsClientID, "definitely-not-the-secret")

	suite.Equal(http.StatusUnauthorized, status, "body: %v", body)
	suite.Equal("invalid_client", body["error"])
}
