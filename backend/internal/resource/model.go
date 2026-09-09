// Copyright 2025 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"github.com/thunder-id/thunderid/internal/sharing"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

// HTTP Response Models

// ResourceServerResponse represents a resource server.
type ResourceServerResponse struct {
	ID          string                       `json:"id"`
	Name        string                       `json:"name"`
	Description string                       `json:"description,omitempty"`
	Identifier  string                       `json:"identifier"`
	Type        providers.ResourceServerType `json:"type"`
	OUID        string                       `json:"ouId"`
	Delimiter   string                       `json:"delimiter"`
	IsReadOnly  bool                         `json:"isReadOnly"`
}

// ResourceResponse represents a resource.
type ResourceResponse struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Handle      string  `json:"handle"`
	Description string  `json:"description,omitempty"`
	Parent      *string `json:"parent,omitempty"`
	Permission  string  `json:"permission"`
}

// ActionResponse represents an action.
type ActionResponse struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Handle      string               `json:"handle"`
	Description string               `json:"description,omitempty"`
	Permission  string               `json:"permission"`
	Kind        providers.ActionKind `json:"kind,omitempty"`
}

// LinkResponse represents a pagination link.
type LinkResponse struct {
	Href string `json:"href"`
	Rel  string `json:"rel"`
}

// ResourceServerListResponse represents the response for listing resource servers.
type ResourceServerListResponse struct {
	TotalResults    int                      `json:"totalResults"`
	StartIndex      int                      `json:"startIndex"`
	Count           int                      `json:"count"`
	ResourceServers []ResourceServerResponse `json:"resourceServers"`
	Links           []LinkResponse           `json:"links"`
}

// ResourceListResponse represents the response for listing resources.
type ResourceListResponse struct {
	TotalResults int                `json:"totalResults"`
	StartIndex   int                `json:"startIndex"`
	Count        int                `json:"count"`
	Resources    []ResourceResponse `json:"resources"`
	Links        []LinkResponse     `json:"links"`
}

// ActionListResponse represents the response for listing actions.
type ActionListResponse struct {
	TotalResults int              `json:"totalResults"`
	StartIndex   int              `json:"startIndex"`
	Count        int              `json:"count"`
	Actions      []ActionResponse `json:"actions"`
	Links        []LinkResponse   `json:"links"`
}

// CreateResourceServerRequest represents the request to create a resource server.
type CreateResourceServerRequest struct {
	Name        string                       `json:"name"                  native:"required"`
	Description string                       `json:"description,omitempty"`
	Identifier  string                       `json:"identifier"            native:"required"`
	Type        providers.ResourceServerType `json:"type,omitempty"`
	OUID        string                       `json:"ouId"                  native:"required"`
	Delimiter   string                       `json:"delimiter,omitempty"`
}

// UpdateResourceServerRequest represents the request to update a resource server.
type UpdateResourceServerRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Identifier  string `json:"identifier,omitempty"`
	OUID        string `json:"ouId"                  native:"required"`
}

// CreateResourceRequest represents the request to create a resource.
type CreateResourceRequest struct {
	Name        string  `json:"name"`
	Handle      string  `json:"handle"                native:"required,max=100"`
	Description string  `json:"description,omitempty"`
	Parent      *string `json:"parent"`
}

// UpdateResourceRequest represents the request to update a resource.
type UpdateResourceRequest struct {
	Name        string `json:"name"                  native:"required"`
	Description string `json:"description,omitempty"`
}

// CreateActionRequest represents the request to create an action.
type CreateActionRequest struct {
	Name        string               `json:"name"                  native:"required"`
	Handle      string               `json:"handle"                native:"required,max=100"`
	Description string               `json:"description,omitempty"`
	Kind        providers.ActionKind `json:"kind,omitempty"`
}

// UpdateActionRequest represents the request to update an action.
type UpdateActionRequest struct {
	Name        string `json:"name"                  native:"required"`
	Description string `json:"description,omitempty"`
}

// Link represents a pagination link in the service layer.
type Link struct {
	Href string
	Rel  string
}

// ResourceServerList represents the result of listing resource servers.
type ResourceServerList struct {
	TotalResults    int
	StartIndex      int
	Count           int
	ResourceServers []providers.ResourceServer
	Links           []Link
}

// ResourceList represents the result of listing resources.
type ResourceList struct {
	TotalResults int
	StartIndex   int
	Count        int
	Resources    []providers.Resource
	Links        []Link
}

// ActionList represents the result of listing actions.
type ActionList struct {
	TotalResults int
	StartIndex   int
	Count        int
	Actions      []providers.Action
	Links        []Link
}

// ShareRequest represents the request body for creating a grant on a resource server,
// resource, or action. Exactly one of three target-scope modes must be selected: root-targeting
// (allRoots or rootOuIds — only valid when ouId is the node's own owning organization unit),
// children-targeting (allChildren or ouIds — valid for any currently-visible ouId), or
// deployment-wide (allOus — owner-only). See role.ShareRequest, which this mirrors; there is no
// editableFields field here, since resource servers/resources/actions declare no templated fields.
//
// The yaml tags carry the same shape through the declarative/bootstrap import path (a
// resource_server document's grants block), so a declared grant and a live API call are
// indistinguishable to the sharing framework. The json tags remain the REST contract.
type ShareRequest struct {
	// OUID is the organization unit performing this share. Optional; defaults to the node's own
	// owning organization unit (its resource server's OUID) when omitted.
	OUID string `json:"ouId,omitempty" yaml:"ouId,omitempty"`
	// AllOUs shares to every organization unit in the deployment at every depth, current and
	// future. Owner-only, and mutually exclusive with every other target-scope field. Unlike
	// AllRoots this reaches descendants too. Reserved for a resource server the whole deployment
	// must always see (the System resource server); ordinary distribution names its recipients.
	AllOUs    bool     `json:"allOus,omitempty"    yaml:"allOus,omitempty"`
	AllRoots  bool     `json:"allRoots,omitempty"  yaml:"allRoots,omitempty"`
	RootOUIDs []string `json:"rootOuIds,omitempty" yaml:"rootOuIds,omitempty"`
	// ExcludedRootOUIDs carves these Root OUs (and their subtrees) out of an AllRoots share.
	ExcludedRootOUIDs []string `json:"excludedRootOuIds,omitempty" yaml:"excludedRootOuIds,omitempty"`
	AllChildren       bool     `json:"allChildren,omitempty"       yaml:"allChildren,omitempty"`
	// OUIDs, when set, must each be a direct child of ouId.
	OUIDs []string `json:"ouIds,omitempty" yaml:"ouIds,omitempty"`
	// ExcludedOUIDs carves these OUs (and their subtrees) out of an AllChildren share, or out of
	// an AllOUs share.
	ExcludedOUIDs []string `json:"excludedOuIds,omitempty" yaml:"excludedOuIds,omitempty"`
	// ExcludedNodeIDs names specific descendant resource/action IDs to leave out of the cascade
	// share this request otherwise performs (e.g. share a resource but withhold one action).
	// Ignored on a leaf Action's own share request, which has no descendants to cascade to.
	ExcludedNodeIDs []string `json:"excludedNodeIds,omitempty" yaml:"excludedNodeIds,omitempty"`
}

// ToSharePolicy converts req's target-scope fields into the sharing.SharePolicy Share() expects.
func (req ShareRequest) ToSharePolicy() sharing.SharePolicy {
	return sharing.SharePolicy{
		AllOUs:            req.AllOUs,
		AllRoots:          req.AllRoots,
		RootOUIDs:         req.RootOUIDs,
		ExcludedRootOUIDs: req.ExcludedRootOUIDs,
		AllChildren:       req.AllChildren,
		OUIDs:             req.OUIDs,
		ExcludedOUIDs:     req.ExcludedOUIDs,
	}
}

// GrantInfo represents a single grant created for, or recorded against, one specific
// node in the resource server/resource/action tree. NodeType/NodeID identify which node this
// grant covers — necessary because a single cascade share (§5.1 of the design doc) creates grants
// across several different nodes (and node types) in one call.
type GrantInfo struct {
	ID            string
	NodeType      string
	NodeID        string
	Stage         string
	TargetScope   string
	TargetOUID    string
	OwningOUID    string
	ExcludedOUIDs []string
}

// GrantResponse represents a single grant over HTTP.
type GrantResponse struct {
	ID            string   `json:"id"`
	NodeType      string   `json:"nodeType"`
	NodeID        string   `json:"nodeId"`
	Stage         string   `json:"stage"`
	TargetScope   string   `json:"targetScope"`
	TargetOUID    string   `json:"targetOuId,omitempty"`
	OwningOUID    string   `json:"owningOuId"`
	ExcludedOUIDs []string `json:"excludedOuIds,omitempty"`
}

// GrantListResponse represents the response for listing or creating grants.
type GrantListResponse struct {
	Grants []GrantResponse `json:"grants"`
}
