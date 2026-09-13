// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"net/http"

	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"

	"github.com/thunder-id/thunderid/internal/oauth/oauth2/constants"
	syscontext "github.com/thunder-id/thunderid/internal/system/context"
	"github.com/thunder-id/thunderid/internal/system/log"
	"github.com/thunder-id/thunderid/internal/system/utils"
)

// accessingOUMiddleware resolves the organization unit named by the /ou/{ouId} prefix and records
// it on the request context, once, for everything downstream: client resolution decides whether the
// client may be used there at all, and token issuance scopes claims and permissions to it.
//
// The existence check belongs here rather than in a grant handler because it is a property of the
// request, not of any one grant type: an id naming nothing still satisfies a blanket all_ous grant,
// so without this it would survive admission and fail much later, during claim resolution, as a
// 500. Refusing it at the edge also keeps every grant type consistent as more of them adopt the
// prefix.
//
// The refusal is deliberately the same unauthorized_client an ungranted organization unit gets.
// Making "no such organization unit" indistinguishable from "not granted to you" is what stops the
// endpoint being used to enumerate organization units.
//
// A request without the prefix passes straight through and is untouched, which is what keeps the
// bare /oauth2/token endpoint behaving exactly as it did before the prefix existed.
func accessingOUMiddleware(ouService providers.OrganizationUnitProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			accessingOUID := r.PathValue(constants.PathParamOUID)
			if accessingOUID == "" {
				next.ServeHTTP(w, r)
				return
			}

			ctx := r.Context()
			if ouService != nil {
				if _, svcErr := ouService.GetOrganizationUnit(ctx, accessingOUID); svcErr != nil {
					logger := log.GetLogger().With(
						log.String(log.LoggerKeyComponentName, "AccessingOUMiddleware"))
					logger.Debug(ctx, "Token requested against an unresolvable organization unit",
						log.String("ouID", accessingOUID))
					utils.WriteJSONError(ctx, w, constants.ErrorUnauthorizedClient,
						"The client is not authorized for the requested organization unit",
						http.StatusBadRequest, nil)
					return
				}
			}

			next.ServeHTTP(w, r.WithContext(syscontext.WithAccessingOUID(ctx, accessingOUID)))
		})
	}
}
