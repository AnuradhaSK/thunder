// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package sharing

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/system/config"
	"github.com/thunder-id/thunderid/internal/system/database/provider"
	"github.com/thunder-id/thunderid/tests/mocks/database/providermock"
	"github.com/thunder-id/thunderid/tests/mocks/oumock"
)

// InitTestSuite tests Initialize.
type InitTestSuite struct {
	suite.Suite
}

func TestInitTestSuite(t *testing.T) {
	suite.Run(t, new(InitTestSuite))
}

func (suite *InitTestSuite) SetupSuite() {
	suite.Require().NoError(config.InitializeServerRuntime("/tmp/test", &config.Config{}))
}

func (suite *InitTestSuite) TestInitialize_Success_NoCacheManager() {
	mockClient := providermock.NewDBClientInterfaceMock(suite.T())
	mockClient.On("GetTransactioner").Return(&fakeTransactioner{}, nil)
	mockProvider := providermock.NewDBProviderInterfaceMock(suite.T())
	mockProvider.On("GetConfigDBClient").Return(mockClient, nil)

	original := getDBProvider
	getDBProvider = func() provider.DBProviderInterface { return mockProvider }
	defer func() { getDBProvider = original }()

	mockOUService := oumock.NewOrganizationUnitServiceInterfaceMock(suite.T())

	svc, err := Initialize(nil, &fakeOUHierarchyResolver{}, mockOUService, false)

	suite.NoError(err)
	suite.NotNil(svc)
}

func (suite *InitTestSuite) TestInitialize_StoreError() {
	mockProvider := providermock.NewDBProviderInterfaceMock(suite.T())
	mockProvider.On("GetConfigDBClient").Return(nil, errBoom)

	original := getDBProvider
	getDBProvider = func() provider.DBProviderInterface { return mockProvider }
	defer func() { getDBProvider = original }()

	_, err := Initialize(nil, &fakeOUHierarchyResolver{}, nil, false)

	suite.Error(err)
}
