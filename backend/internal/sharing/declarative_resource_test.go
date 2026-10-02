// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package sharing

import (
	"context"
	"testing"

	"github.com/stretchr/testify/suite"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

// DeclarativeResourceTestSuite covers what the loader does with the sharing half of a resource's
// document: every policy it carries is declared, and a refusal stops startup saying which one.
type DeclarativeResourceTestSuite struct {
	suite.Suite
	svc   *declaringServiceStub
	seeds *policySeeder
}

func TestDeclarativeResourceTestSuite(t *testing.T) {
	suite.Run(t, new(DeclarativeResourceTestSuite))
}

func (s *DeclarativeResourceTestSuite) SetupTest() {
	s.svc = &declaringServiceStub{}
	s.seeds = &policySeeder{ctx: context.Background(), svc: s.svc, rt: testType}
}

// declaringServiceStub records what was declared, and can refuse on command. The service interface
// is large and only one method is exercised here, so the stub embeds it rather than implementing
// every method: a call to any other panics, which is the right answer if one ever appears.
type declaringServiceStub struct {
	SharingServiceInterface
	declared []PolicyRequest
	refuse   *tidcommon.ServiceError
}

func (d *declaringServiceStub) CreateDeclarativePolicy(
	_ context.Context, _ ResourceType, _, _ string, req PolicyRequest,
) (Policy, *tidcommon.ServiceError) {
	if d.refuse != nil {
		return Policy{}, d.refuse
	}
	d.declared = append(d.declared, req)
	return Policy{ID: req.ID}, nil
}

// declaredDocument is the sharing half of one document, carrying two policies: the owner's, and a
// reshare issued by an organization unit it reaches. That is the only shape a document carrying two
// policies can take, since one organization unit holds one policy per resource.
func declaredDocument() *DeclaredResourcePolicies {
	return &DeclaredResourcePolicies{
		ResourceID:   testResource,
		ResourceName: "the-resource",
		OwningOUID:   ownerOU,
		Policies: []providers.SharingPolicy{
			{ID: declaredID, TargetOuScope: providers.SharingTargetOUScope{AllOUs: true}},
			{
				ID:             "a-second-policy",
				InitiatingOuID: rootOU,
				TargetOuScope:  providers.SharingTargetOUScope{AllChildren: true},
			},
		},
	}
}

// Every policy a document carries is declared, in the order the document lists them, because a
// reshare may name the policy above it and would not find one that had not been declared yet.
func (s *DeclarativeResourceTestSuite) TestEveryPolicyInADocumentIsDeclared() {
	s.Require().NoError(s.seeds.Create(testResource, declaredDocument()))

	s.Require().Len(s.svc.declared, 2)
	s.Equal(declaredID, s.svc.declared[0].ID)
	s.True(s.svc.declared[0].TargetOUScope.AllOUs)
	s.Equal("a-second-policy", s.svc.declared[1].ID)
	s.True(s.svc.declared[1].TargetOUScope.AllChildren)
}

// A refused declaration stops startup, and says which resource and which policy, so the operator is
// not left searching the directory for the document that is wrong.
func (s *DeclarativeResourceTestSuite) TestARefusalNamesTheResourceAndThePolicy() {
	s.svc.refuse = &tidcommon.InternalServerError

	err := s.seeds.Create(testResource, declaredDocument())

	s.Require().Error(err)
	s.Contains(err.Error(), "the-resource", "the failure names the resource")
	s.Contains(err.Error(), "policy 1", "and which of its policies")
	s.Contains(err.Error(), ownerOU, "and the organization unit the policy was issued by")
	s.Contains(err.Error(), tidcommon.InternalServerError.Code, "and what the framework said")
}

// A policy naming its own initiator is reported against that unit rather than against the owner,
// which is what tells two policies on one document apart.
func (s *DeclarativeResourceTestSuite) TestARefusalNamesTheInitiatorWhenOneIsGiven() {
	s.svc.refuse = &tidcommon.InternalServerError
	doc := declaredDocument()
	doc.Policies = doc.Policies[:1]
	doc.Policies[0].InitiatingOuID = rootOU

	err := s.seeds.Create(testResource, doc)

	s.Require().Error(err)
	s.Contains(err.Error(), rootOU)
}

// Two policies for one organization unit are refused before either is declared, because seeding
// would otherwise replace the first with the second and say nothing.
func (s *DeclarativeResourceTestSuite) TestTwoPoliciesForOneInitiatorAreRefused() {
	doc := declaredDocument()
	doc.Policies[1].InitiatingOuID = ""

	err := s.seeds.Create(testResource, doc)

	s.Require().Error(err)
	s.Contains(err.Error(), "the-resource", "the failure names the document")
	s.Contains(err.Error(), "policies 1 and 2", "and which two policies collide")
	s.Contains(err.Error(), ownerOU, "and the organization unit they both govern")
	s.Empty(s.svc.declared, "nothing is declared from a document that is refused")
}

// The same applies when the duplicate is spelled out rather than left to default to the owner.
func (s *DeclarativeResourceTestSuite) TestADuplicateInitiatorIsCaughtWhenNamedExplicitly() {
	doc := declaredDocument()
	doc.Policies[0].InitiatingOuID = rootOU

	err := s.seeds.Create(testResource, doc)

	s.Require().Error(err)
	s.Contains(err.Error(), rootOU)
	s.Empty(s.svc.declared)
}

// A document whose policies name different organization units is the reshare case and is untouched.
func (s *DeclarativeResourceTestSuite) TestPoliciesForDifferentInitiatorsAreDeclared() {
	s.Require().NoError(s.seeds.Create(testResource, declaredDocument()))

	s.Len(s.svc.declared, 2)
}

// A document declaring nothing is the ordinary case and must not reach the framework at all.
func (s *DeclarativeResourceTestSuite) TestADocumentDeclaringNothingIsNotAFailure() {
	s.Require().NoError(s.seeds.Create(testResource, &DeclaredResourcePolicies{ResourceID: testResource}))
	s.Require().NoError(s.seeds.Create(testResource, (*DeclaredResourcePolicies)(nil)))

	s.Empty(s.svc.declared)
}

// Anything that is not a policy bundle is a programming error in the consumer's parser, and is
// reported as one rather than silently skipped.
func (s *DeclarativeResourceTestSuite) TestAnUnexpectedTypeIsReported() {
	err := s.seeds.Create(testResource, "not a bundle")

	s.Require().Error(err)
	s.Contains(err.Error(), "unexpected data type")
}

// A deployment that loads no declarative resources has no file store, and asking it to load is a
// no-op rather than a failure, so a consumer may call it without checking first.
func (s *DeclarativeResourceTestSuite) TestLoadingWithoutAFileStoreIsANoOp() {
	err := loadDeclarativeResources(context.Background(), s.svc, nil, DeclarativeLoaderConfig{
		ResourceType: testType, DirectoryName: "whatever",
	})

	s.Require().NoError(err)
	s.Empty(s.svc.declared)
}
