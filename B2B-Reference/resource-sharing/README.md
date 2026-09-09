# Resource Sharing B2B Demo - Postman Collection

This collection exercises the B2B sharing of resource servers, resources, and actions across
organization units (OUs), the same generic `internal/sharing` framework that already powers Role
sharing (see [B2B-Reference/role-sharing](../role-sharing)), applied to the permission catalog
itself instead of to roles. See
[B2B_RESOURCE_SHARING_DESIGN.md](../B2B_RESOURCE_SHARING_DESIGN.md) for the full design and
[api/resource.yaml](../../api/resource.yaml) for the REST API reference these requests exercise.

The generic OU-targeting mechanics this feature inherits unchanged from `internal/sharing`
(`allRoots`/`allChildren`/`rootOuIds`/`ouIds`, exclusion semantics, one-hop delegation chains,
cross-tree restrictions) are already fully proven by
[B2B-Reference/role-sharing](../role-sharing) and are **not** re-derived here. This collection is
scoped to what is actually new about sharing a tree of resource servers, resources, and actions
instead of a flat catalog of roles:

- Three separate sharing-framework resource types (`resource_server`, `resource`, `action`) rather
  than one, so a specific action can be withheld while its sibling is shared.
- **Cascade share**: sharing a resource server (or a non-leaf resource) with `allChildren`/root
  targeting fans out to every resource/action currently beneath it in one call.
- **Cascade exclusion via `excludedNodeIds`**: a field unique to this feature, not present on
  Role's `ShareRequest`, letting a cascade share withhold specific descendants.
- **Auto-inherit on creation**: a new action created under an already-shared resource becomes
  visible to the sharee immediately, with no separate share call.
- **Cascade unshare**: revoking the top-level grant tears down every descendant grant created
  alongside it by that same cascade call, including ones later individually reshared or
  auto-inherited.
- **The compound RBAC check**, the actual point of the whole feature: a role's stored permissions
  are not enough by themselves. A permission is only usable at token-issuance time while its
  resource server *and* the specific resource/action it names are currently shared to the acting
  OU, re-evaluated fresh on every request, independent of whatever the role itself still records.
- **Write-time defense in depth**: a role write naming a permission not currently visible to its
  own OU is rejected outright (`ROL-1025`).
- **The root permission bypass**: the bare deployment root permission keeps full access regardless
  of any resource-sharing state; it is never itself subject to a share/unshare call.
- **The API's own scope tier**: `system:resource-servers` (manage) and `system:resource-servers:view`
  (read-only), plus per-caller OU confinement on top, so a scoped administrator can be refused for
  three distinguishable reasons (`AUTH-4030`, `RES-1024`, `SHR-1007`).

## Collection Structure

```
├── 00 - Setup                                              # OUs, resource server, resource/action tree
├── 01 - Cascade Share of the Resource Server, With Exclusion  # excludedNodeIds, per-node GET scoping
├── 02 - Compound RBAC: Withheld Permission Blocks Real Access # the core scenario
├── 03 - Write-Time Defense in Depth (ROL-1025)              # rejecting an invisible permission at write time
├── 04 - Auto-Inherit on Creation                            # a new action inherits its parent's active share
├── 05 - Cascade Unshare                                     # revoking the top grant tears down every descendant
├── 06 - The Root Permission Bypass                          # the literal deployment root permission
├── 07 - API Authorization: system:resource-servers Scope    # view/manage split plus own-OU confinement
└── 08 - Cleanup                                             # tears down everything this collection created
```

## Scenario

- **A** owns a resource server, **Booking System**, with a top-level resource **Bookings**
  (actions `view` and `create`) and a second top-level resource **Refunds** (action `approve`).
  **B** is a separate Root OU with no relationship to A's resource server until shared.
- `01` shares the whole Booking System resource server to B in a single call, using
  `excludedNodeIds` to withhold **Refunds and its own `approve` action** from the cascade. Both
  ids must be listed explicitly: excluding a non-leaf resource does not implicitly exclude its own
  descendants (`backend/internal/resource/sharing.go`'s descendant enumeration and exclusion check
  are independent of tree nesting), a nuance this folder deliberately surfaces. Refunds/`approve`
  stay withheld from B for the rest of the collection, standing in for "a permission this OU can
  never see" in `03`'s negative tests.
- An **application** (`Booking App`) is created directly in B and assigned to a role, `booking-ops`,
  owned by B and naming both `bookings:view` and `bookings:create`, both visible to B at role
  creation time. `02` then unshares just the `create` action's own grant, leaving the resource
  server and Bookings resource themselves still shared, and walks the full consequence:
  - Unsharing strips `bookings:create` from `booking-ops` outright. The role's own stored
    permission list stops naming it, which the folder inspects directly with a `GET /roles/{id}`.
    A role never keeps claiming access it can no longer use.
  - A fresh token then carries only `bookings:view`, confirming the runtime effect.
  - Resharing `create` restores B's *visibility* of the action, but **not** the role's grant: the
    permission was removed, so it has to be re-added deliberately with a `PUT /roles/{id}`. That
    update succeeds only because the action is visible again; the identical request while it was
    unshared is rejected with `ROL-1025`, which is exactly what `03` proves.
  - A final token then carries both permissions again.

  This is the single most important sequence in the collection. Sharing state is enforced fresh at
  every token issuance rather than baked into the role at write time, and revoking a share is a
  durable change to what the affected roles grant, not a temporary filter that silently reverses
  itself the moment someone reshares.
- `03` uses the withheld `refunds:approve` permission from the initial exclusion to prove a role
  write naming it is rejected outright (`ROL-1025`), both on an existing role's update and on a
  brand new role's creation, with a control request showing the identical write succeeds once it
  names only currently-visible permissions.
- `04` creates a third action, `cancel`, under the already-shared Bookings resource, and shows it
  already carries a grant to B with no separate share call, then proves it beyond mere
  bookkeeping by adding it to `booking-ops` and minting a token that includes it.
- `05` revokes the resource server's own top-level grant from `01` and shows every descendant grant
  disappears with it: `view`'s original cascade grant, `create`'s reshare from `02` (which targeted
  the identical OU selection as the top grant, so it is swept up by symmetry), and `cancel`'s
  auto-inherited grant from `04`, which was never itself the subject of a direct share call at all.
  A final token request confirms none of Bookings' permissions remain usable.
- `06` looks up the bootstrap System resource server's own `system` resource, whose derived
  permission is the literal deployment root permission, and creates a role in B naming only that
  permission. Both the write (role creation) and the read (token issuance) succeed because the root
  permission is a categorical bypass, evaluated before any visibility check runs. Note this one
  permission would succeed even with no grant anywhere, which is exactly why it is a poor
  probe for sharing behavior: `07` uses ordinary sub-resource permissions instead.
- `07` steps away from the sharing model to pin the Resource Management API's own authorization
  boundary, mirroring `B2B-Reference/role-sharing`'s folders `12`/`13` for Role. It nests
  `resource-servers` and `view` resources under the System resource server's `system` resource to
  derive the `system:resource-servers` and `system:resource-servers:view` permission strings, then
  mints two narrow `client_credentials` tokens from two m2m applications **in B**, so both tokens
  carry B (the sharee, not the owner) as their `ouId` claim. All three refusal layers answer `403`,
  so each request asserts the specific error `code` to keep them apart:
  - `AUTH-4030`, the security middleware, when the scope itself is insufficient. The view-only
    token gets this on create, update, delete, and share, all four targeting nodes it can read.
    Sharing is a manage operation: the read-only tier can list grants but never create one. A token
    holding neither scope gets it on `/resource-servers` outright, read included.
  - `RES-1024`, `internal/resource`'s own `requireOwnOUScope`/`RequireVisibility`, when the scope is
    right but the target OU is not the caller's own. The manage token cannot create a resource
    server in A, nor a resource or action under A's, and cannot read Refunds or its `approve`
    action, which no cascade ever shared to B. It *can* read Bookings, the share fallback's
    positive contrast, and can create, update, share, and delete a resource server in B, its own
    OU, the whole lifecycle without ever holding the root permission.
  - `SHR-1007`, the sharing framework's ownership invariant, on update and delete of A's resource
    server: those paths defer to `sharing.RequireOwnership`, so share visibility never confers the
    right to edit core configuration. `internal/resource` declares no deletion-specific ownership
    error of its own, unlike `internal/role`, so delete reports the same code as an update.

  The scoped listing (`GET /resource-servers`) is confined to the caller's own organization unit,
  so it returns what B owns plus what is shared to B, never the deployment. Note the System
  resource server **is** in that listing, and must be: it is shared to every organization unit at
  bootstrap so each one can see the permissions that gate the management APIs. A dedicated,
  never-shared resource server in A is created purely to give the confinement assertion something
  that genuinely must not appear.

  The folder re-shares A's resource server to B at the start (folder `05` tore every grant down)
  and revokes that grant again at the end, so it leaves the collection's sharing state as it found
  it. The confinement-control resource server it creates is removed in `08 - Cleanup`.

## Prerequisites

1. A running ThunderID server.
2. A client registered for the `client_credentials` grant with the `system` scope, authenticating
   with HTTP Basic auth (client ID and secret in the `Authorization` header). Its token
   (`00`'s `Get Access Token`) is the bearer credential used by every request in the collection
   except the application client_credentials token requests.
3. Postman desktop app or web version.

## Environment Setup

Import `environment.json` and fill in:

| Variable | Description | Example |
|----------|-------------|---------|
| `scheme` | Server scheme | `https` |
| `host` | Server host | `localhost` |
| `port` | Server port | `8090` |
| `baseUrl` | Server base URL | `{{scheme}}://{{host}}:{{port}}` |
| `clientId` | Client ID for the system-scoped `client_credentials` client | |
| `clientSecret` | Client secret for the same client | |

`accessToken` and every resource ID (`aOuId`, `bOuId`, `resourceServerId`, `bookingsResourceId`,
`bookingOpsRoleId`, etc.) are collection variables that get populated automatically as the requests
run; they do not need to be set up front. `systemResourceServerId` is a collection variable
prefilled with the bootstrap-fixed id of the deployment's default "System" resource server (the
same constant `B2B-Reference/role-sharing` uses), not something this collection creates itself.

## Usage

Run the folders in order, top to bottom, request by request. Each request's `test` script asserts
the expected status code and, where relevant, the specific response fields or error `code`
documented in `api/resource.yaml`; failures show up directly in Postman's test results, not just
as raw response bodies.

Run **08 - Cleanup** at the end of each pass, or the fixed `handle` values used in **00 - Setup**
(`resource-sharing-a`, `resource-sharing-b`), the resource server's `identifier`, and the
`resource-servers`/`view` sub-resources **07** adds under the System resource server will conflict
on the next run.

## Notes

- All requests inherit a collection-level bearer auth using `{{accessToken}}` (the `system`-scoped
  admin token), except the `client_credentials` token requests, which authenticate as the
  application under test via HTTP Basic auth using that application's own client id/secret, and the
  requests in **07**, which override it with one of that folder's narrow scoped tokens.
- This collection creates real data (organization units, a resource server, resources, actions,
  applications, roles). It is independent of, and can be run alongside, `B2B-Reference/role-sharing`
  as long as both are set up against the same server (they use distinct OU handles, a distinct
  resource server identifier, and distinct System sub-resource handles, so they do not conflict).
- `defaultOuId` is a collection variable prefilled with the bootstrap-fixed id of the deployment's
  default organization unit, which owns the System resource server. **07**'s two scope-carrying
  roles are *not* created there: they are owned by B, the same organization unit their applications
  live in. That works because the System resource server is shared to every organization unit at
  bootstrap (`grants: [{allOus: true}]` in
  `backend/cmd/server/bootstrap/01-default-resources.yaml`), so B can see the permissions it
  defines. Owning them in the default organization unit instead would fail in a non-obvious way:
  the write would pass, but the role's assignment would be recorded against the default
  organization unit, and permission resolution is scoped by the assigning organization unit, so a
  token whose `ouId` claim is B would come back with no scopes at all.
