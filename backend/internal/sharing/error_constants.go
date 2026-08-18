// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package sharing

import (
	"errors"

	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
)

// Client errors for the sharing service.
var (
	// ErrorInvalidRequestFormat is returned when a share/reshare request is malformed.
	ErrorInvalidRequestFormat = tidcommon.ServiceError{
		Type: tidcommon.ClientErrorType,
		Code: "SHR-1001",
		Error: tidcommon.I18nMessage{
			Key:          "error.sharingservice.invalid_request_format",
			DefaultValue: "Invalid request format",
		},
		ErrorDescription: tidcommon.I18nMessage{
			Key:          "error.sharingservice.invalid_request_format_description",
			DefaultValue: "The request body is malformed or contains invalid data",
		},
	}
	// ErrorResourceTypeNotRegistered is returned when the given resource type has no declaration
	// registered with the sharing framework.
	ErrorResourceTypeNotRegistered = tidcommon.ServiceError{
		Type: tidcommon.ClientErrorType,
		Code: "SHR-1002",
		Error: tidcommon.I18nMessage{
			Key:          "error.sharingservice.resource_type_not_registered",
			DefaultValue: "Resource type not registered",
		},
		ErrorDescription: tidcommon.I18nMessage{
			Key:          "error.sharingservice.resource_type_not_registered_description",
			DefaultValue: "The given resource type has not been registered with the sharing framework",
		},
	}
	// ErrorGrantNotFound is returned when a referenced grant does not exist.
	ErrorGrantNotFound = tidcommon.ServiceError{
		Type: tidcommon.ClientErrorType,
		Code: "SHR-1003",
		Error: tidcommon.I18nMessage{
			Key:          "error.sharingservice.grant_not_found",
			DefaultValue: "Grant not found",
		},
		ErrorDescription: tidcommon.I18nMessage{
			Key:          "error.sharingservice.grant_not_found_description",
			DefaultValue: "The grant with the specified id does not exist",
		},
	}
	// ErrorInvalidTargetOU is returned when a target OU does not satisfy the policy's constraints
	// (e.g. a share target that is not a Root OU, or a reshare target outside the Root's subtree).
	ErrorInvalidTargetOU = tidcommon.ServiceError{
		Type: tidcommon.ClientErrorType,
		Code: "SHR-1004",
		Error: tidcommon.I18nMessage{
			Key:          "error.sharingservice.invalid_target_ou",
			DefaultValue: "Invalid target organization unit",
		},
		ErrorDescription: tidcommon.I18nMessage{
			Key:          "error.sharingservice.invalid_target_ou_description",
			DefaultValue: "The target organization unit does not satisfy the sharing policy's constraints",
		},
	}
	// ErrorNotShared is returned when a reshare or write-path check finds no valid share/reshare
	// grant making the resource visible to the given OU.
	ErrorNotShared = tidcommon.ServiceError{
		Type: tidcommon.ClientErrorType,
		Code: "SHR-1005",
		Error: tidcommon.I18nMessage{
			Key:          "error.sharingservice.not_shared",
			DefaultValue: "Resource not shared to this organization unit",
		},
		ErrorDescription: tidcommon.I18nMessage{
			Key:          "error.sharingservice.not_shared_description",
			DefaultValue: "The resource has not been shared or reshared to the given organization unit",
		},
	}
	// ErrorFieldNotTemplated is returned when a share/reshare request's EditableFields names a
	// field the resource type has not declared as templated.
	ErrorFieldNotTemplated = tidcommon.ServiceError{
		Type: tidcommon.ClientErrorType,
		Code: "SHR-1006",
		Error: tidcommon.I18nMessage{
			Key:          "error.sharingservice.field_not_templated",
			DefaultValue: "Field is not a templated field",
		},
		ErrorDescription: tidcommon.I18nMessage{
			Key:          "error.sharingservice.field_not_templated_description",
			DefaultValue: "The given field is not declared as a templated field for this resource type",
		},
	}
	// ErrorCoreConfigOwnerOnly is returned when a caller who is not the resource's owning
	// organization unit (and does not hold the deployment's root permission) attempts to create,
	// modify, or delete a resource's core (non-templated) configuration.
	ErrorCoreConfigOwnerOnly = tidcommon.ServiceError{
		Type: tidcommon.ClientErrorType,
		Code: "SHR-1007",
		Error: tidcommon.I18nMessage{
			Key:          "error.sharingservice.core_config_owner_only",
			DefaultValue: "Core configuration can only be modified by the owning organization unit",
		},
		ErrorDescription: tidcommon.I18nMessage{
			Key: "error.sharingservice.core_config_owner_only_description",
			DefaultValue: "The caller's organization unit does not own this resource; only the owning " +
				"organization unit, or an unrestricted caller, may create, modify, or delete its core configuration",
		},
	}
	// ErrorEditabilityCannotBeExpanded is returned when a reshare's EditableFields names a field
	// the acting organization unit is not itself currently permitted to edit: a reshare may only
	// narrow editability relative to what the resharing organization unit itself holds, never
	// widen it.
	ErrorEditabilityCannotBeExpanded = tidcommon.ServiceError{
		Type: tidcommon.ClientErrorType,
		Code: "SHR-1008",
		Error: tidcommon.I18nMessage{
			Key:          "error.sharingservice.editability_cannot_be_expanded",
			DefaultValue: "Editability cannot be expanded on reshare",
		},
		ErrorDescription: tidcommon.I18nMessage{
			Key: "error.sharingservice.editability_cannot_be_expanded_description",
			DefaultValue: "A reshare may only narrow which templated fields are editable relative to what the " +
				"acting organization unit itself currently holds, never widen it",
		},
	}
	// ErrorCrossTreeShareRestricted is returned when a non-root organization unit uses
	// root-targeting to share a resource directly to a root outside its own tree. A non-root
	// owner may always push a share up to its own tree's root (the standard first step of the
	// push-to-own-root-then-reshare pattern); reaching a foreign tree's root instead requires the
	// deployment's resource_sharing.allow_child_ou_cross_tree_sharing config (deployment.yaml, a
	// static setting applied at startup) to be enabled. A root organization unit is never subject
	// to this check — sharing directly to another root is ordinary Root-to-Root distribution, not
	// a child reaching outside its own tree. The message is deliberately generic: it does not
	// reveal the target's relationship to the deployment's organization structure or the existence
	// of a server-side sharing configuration to the caller.
	ErrorCrossTreeShareRestricted = tidcommon.ServiceError{
		Type: tidcommon.ClientErrorType,
		Code: "SHR-1009",
		Error: tidcommon.I18nMessage{
			Key:          "error.sharingservice.cross_tree_share_restricted",
			DefaultValue: "Sharing is not allowed",
		},
		ErrorDescription: tidcommon.I18nMessage{
			Key:          "error.sharingservice.cross_tree_share_restricted_description",
			DefaultValue: "The organization unit is not allowed to share this resource to the requested target",
		},
	}
	// ErrorGrantDeclarative is returned when a caller tries to modify a grant that a declarative
	// resource file declares. The file owns it, so it changes only by editing the file.
	ErrorGrantDeclarative = tidcommon.ServiceError{
		Type: tidcommon.ClientErrorType,
		Code: "SHR-1010",
		Error: tidcommon.I18nMessage{
			Key:          "error.sharingservice.grant_declarative",
			DefaultValue: "Grant cannot be modified",
		},
		ErrorDescription: tidcommon.I18nMessage{
			Key:          "error.sharingservice.grant_declarative_description",
			DefaultValue: "The grant is defined in a declarative resource file and can only be changed there",
		},
	}
)

// Internal sentinel errors for the sharing store.
var (
	// ErrGrantNotFound is returned by the store when a grant id does not exist.
	ErrGrantNotFound = errors.New("grant not found")
	// ErrGrantDeclarative is returned by the store when a mutation targets a grant held in the
	// declarative store rather than the database.
	ErrGrantDeclarative = errors.New("grant is declarative")
)
