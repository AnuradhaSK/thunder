# Role B2B Sharing Demo - Postman Collection

This collection exercises the Role sharing framework end to end: creating a role, sharing it to a
Root organization unit, resharing it into that Root's subtree (including "all except" exclusion
policies), a single-call share when the owner already sits at the top of its own subtree, a
two-step push-to-own-root path when a non-root owner needs to reach outside its own subtree, the
default restriction on a non-root owner sharing directly to a *foreign* tree's Root, one-hop-at-a-
time delegation chains and their integrity under exclusion, controlling
templated-field editability as a property of the grant itself — independently per assignee
type (and via a blanket fallback field), with a reshare only ever able to narrow it relative to
what the resharing organization unit itself holds — proving non-owner organizations can own roles of
their own alongside shared ones, listing roles at the OU level with the `origin` tag, and proving a
shared role's assignment is honored by real `client_credentials` token issuance (RBAC). Both
sharing and resharing are issued through the single `POST /roles/{id}/grants` endpoint (a
sub-resource creation call,
alongside the existing `GET`/`DELETE` on the same path for listing and revocation) — there is no
separate `/share` or `/reshare` action endpoint. It also exercises the Role Management API's own
token-scope + OU restriction (`system` vs. `system:roles` vs. `system:roles:view`), independent of
the sharing model above, and proves a shared role's grants and per-sharee-OU assignments survive a
full `POST /export` -> delete -> `POST /import` round trip.
See [api/role.yaml](../../../../api/role.yaml) for the full REST API reference these requests
exercise.

## Collection Structure

```
├── 00 - Setup                                        # system:roles infra, OUs, resource server, groups
├── 01 - Role Creation & Core Config                  # Create the role, confirm owned/shared listing behavior
├── 02 - Roles Owned by B and B-sub1                    # Each owns a role of its own too
├── 03 - Share to Root                                # Owner -> Root organization unit
├── 04 - Reshare into Root's Subtree                  # Root -> its subtree (allChildren)
├── 05 - Exclusion Policy ("All Except")              # excludedRootOuIds / excludedOuIds, on a throwaway role
├── 06 - Editability Control (Grant-Scoped)           # editableFields on a reshare, scope-down-only, per-type + blanket
├── 07 - Negative & Authorization Tests               # Write-path rejections and validation errors
├── 08 - RBAC: Client Credentials Grant for an App    # Shared-role assignment reflected in a real token
├── 09 - Single-Call Owner Distribution               # Owner shares directly to its own children, no prior grant
├── 10 - Cross-Tree Delegation via Push-to-Own-Root   # Non-root owner reaches a sibling OU in two steps; foreign-Root restriction
├── 11 - Chained Delegation and Chain Integrity       # One-hop-at-a-time delegation; per-target allChildren; exclusions
├── 12 - Scoped Admin Client Setup                     # RBAC-assigns system:roles/system:roles:view, mints tokens
├── 13 - API Authorization: system:roles Scope         # Token-scope + OU restriction, view vs. manage, independent of sharing
├── 14 - Revoke Sharing (Unshare Cascade)             # Confirms revocation cascades cleanly
├── 15 - Export/Import Round-Trip                     # A shared role's grants/assignments survive export -> delete -> import
└── 16 - Cleanup                                       # Tears down everything this collection created
```

## Scenario

- **A** owns a role named `regional-manager` with two permissions and one assignment
  (its own group).
- **B** has a pre-existing child, **B-sub1**. Both B and B-sub1 also own a role of their
  own (`02`), independent of anything shared to them. The
  `regional-manager` role is shared to B (`03`), then reshared into its subtree with
  `allChildren: true` (`04`).
- A **B-sub1b** child OU is created *after* the reshare call, to prove `allChildren` is
  evaluated dynamically: no second reshare call is needed for it to see the role. B-sub1b is
  reused later (`10`, `11`, `13`) as a plain, non-excluded sibling for contrast.
- An **Ex-A** has no sharing relationship to the main role at all, used for the
  negative tests (attempting to write assignments without a grant, resharing without a prior
  share, etc). It also stands in for the organization unit deliberately left out of an `allRoots`
  share in `05`, and — belonging to its own, separate tree — stands in for a "foreign Root" that
  `10`'s cross-tree share restriction demo proves B-sub1 cannot reach directly.
- A second, throwaway **Exclusion Demo Role** (`05`) is created, shared, reshared, and deleted
  entirely within its own folder, to demonstrate `excludedRootOuIds`/`excludedOuIds` without
  disturbing the main scenario's organization unit access assumptions.
- An **Application** is created directly in B-sub1 (`08`) and assigned to the shared
  `regional-manager` role there, to prove the assignment is honored by real token issuance, not
  just by the sharing API's own bookkeeping.
- A **demo user** (with a minimal, B-sub1-scoped user type created alongside it) is created
  directly by the collection (`00`), so `06`'s `assignments.user` editability demo assigns a real
  principal instead of depending on an externally-supplied ID.
- A **B-sub2** organization unit (a grandchild of B, created under B-sub1
  within `06`) is reshared to with a narrower `editableFields` than B-sub1 itself
  holds, to demonstrate grant-scoped editability and its scope-down-only rule without touching
  B-sub1's own, broader grant (which other folders, e.g. `14`, still depend on).
- A third, throwaway **Chain Demo Role** and a **B-sub2b** organization unit (a grandchild of
  B, created under B-sub1) exist only within `11`, to demonstrate delegation and
  exclusion two levels deep without touching the main scenario's grants.
- A fourth, throwaway **Export Demo Role** (`15`) is created, shared to B's own children, given a
  B-sub1 assignment, exported, revoked and deleted, then recreated by importing the exported YAML
  back, to prove the round trip restores both the grant and the sharee assignment rather than
  just the role's core config.
- Three throwaway **scoped admin applications** (`12`): one in B and one in B-sub1 mint
  `system:roles`-scoped tokens (plus one token with an unrelated scope) to exercise the API's own
  token-scope + OU restriction in `13`. A token's `ouId` claim always comes from its issuing
  application's own OU, so two different applications are needed to simulate two different caller
  organization units. A third, also registered in B, mints a `system:roles:view`-scoped token to
  exercise the read-only tier's own restriction (list/read allowed, every write rejected) alongside
  the full-access one.

## Prerequisites

1. A running ThunderID server.
2. A client registered for the `client_credentials` grant with the `system` scope, authenticating
   with HTTP Basic auth (client ID and secret in the `Authorization` header). Its token
   (`00`'s `Get Access Token`) is the bearer credential used by every request in the collection.
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

`accessToken` and every resource ID (`aOuId`, `roleId`, `shareGrantId`, `appId`,
`demoUserId`, etc.) are collection variables that get populated automatically as the requests run;
they do not need to be set up front.

## Usage

Run the folders in order, top to bottom, request by request:

1. **00 - Setup**: obtains an access token from the prerequisite client (`Get Access Token`), used
   as the bearer credential for every request in the collection from here on. It then makes the
   bootstrap-fixed **System** resource server (`systemResourceServerId`) the deployment's default
   resource server, looks up that resource server's own top-level resources to resolve the
   `system` resource's id (`systemResourceId`) rather than assuming its id shape, nests a `Roles`
   sub-resource under it (`via parent`) to derive the `system:roles` permission string, nests a
   further `View` sub-resource under `Roles` to derive `system:roles:view` (the Role Management
   API's read-only tier), and creates a **System Roles Manager** role carrying `system:roles` and a
   **System Roles Viewer** role carrying `system:roles:view` — the proper, RBAC-backed way to grant
   either scope to an application, used by `12` (an application's own `inboundAuthConfig.scopes`
   only bounds what it may *request*; the `client_credentials` grant still filters the issued token
   through an actual role assignment, the same as any other permission). It then creates the
   organization unit tree, resource server, permissions, groups, and a demo user (and its user type
   schema) the rest of the collection depends on. The System Roles Manager and Viewer roles and
   their `Roles`/`View` sub-resources are cleaned up in `16 - Cleanup`, but the
   default-resource-server setting and the System resource server/resource themselves are left in
   place as a deliberate, lasting deployment change.
2. **01 - Role Creation & Core Config**: creates the role and confirms `GET /roles` behaves
   correctly with and without `ouId` before any sharing has happened.
3. **02 - Roles Owned by B and B-sub1**: each creates a
   role of their own here, ahead of anything being shared to them. `04` later confirms both
   origins (`owned` and `shared`) appear together in the same listing once the main role arrives.
   These two roles are reused again in `13` to test the token-scope + OU restriction.
4. **03 - Share to Root**: shares the role to B and confirms B itself (but
   not yet its child OUs) can act on it.
5. **04 - Reshare into Root's Subtree**: reshares with `allChildren: true` and confirms both the
   pre-existing child (B-sub1) and a child created afterward (B-sub1b) see the role,
   each with its own independent `assignments`, and that B-sub1's role listing now shows its
   own native role and the shared role side by side with distinct `origin` tags. Confirms the same
   for the organization-unit management API's own role-listing endpoints
   (`GET /organization-units/{id}/roles` and the handle-path form), which reach role data through a
   separate resolver from the Role Management API's own `GET /roles?ouId=` and must independently
   account for sharing rather than listing only owned roles. With two grants now on the role, the
   folder also pages `GET /roles/{id}/grants` one grant at a time, confirming each page
   reports the full `totalResults`, offers the expected `next`/`prev` links, and returns a different
   grant than the page before it.
6. **05 - Exclusion Policy ("All Except")**: on a throwaway second role, shares to all Roots except
   Ex-A, then reshares to all children except B-sub1, confirming the excluded
   organization unit in each step is the only one that doesn't see the role. Cleans up its own
   grants and role at the end of the folder.
7. **06 - Editability Control (Grant-Scoped, Scope-Down-Only)**: B-sub1 reshares further to a
   new grandchild, B-sub2, naming `editableFields: ["assignments.group"]` —
   narrower than B-sub1's own, unrestricted set — and `GET .../editable-fields` confirms the
   resolved set matches exactly. An `assignments.user` write is blocked (not in the grant's
   `editableFields`); an `assignments.group` write (in it) succeeds. `07` covers the corresponding
   negative cases: naming an undeclared field, and a reshare attempting to widen editability beyond
   what the resharing OU itself holds.
8. **07 - Negative & Authorization Tests**: exercises the documented `400`/`403` error codes
   (`ROL-1019`, `SHR-1004`, `SHR-1005`, `SHR-1006`, `SHR-1008`).
9. **08 - RBAC: Client Credentials Grant for an App**: creates an application directly in
   B-sub1, assigns it to the shared role there, and confirms a `client_credentials` token issued to
   that application (also authenticated via HTTP Basic auth) comes back with the role's permissions
   in `scope`, both in the token endpoint's response and decoded directly from the JWT payload. See
   "Known Gap" below.
10. **09 - Single-Call Owner Distribution**: B, which owns a role of its own (from `02`)
    and is itself a Root, shares that role directly to B-sub1 in a single call, with no
    preceding grant needed at all — the owner is always trivially visible to its own resource, so
    a Root owner reaches its own children in one step. The resulting grant's `stage` is `"share"`,
    not `"reshare"`: stage records who issued the grant (the owner, here), not which target-scope
    mode was used.
11. **10 - Cross-Tree Delegation via Push-to-Own-Root**: B-sub1, which is *not* a Root, wants
    its own role (from `02`) to reach B-sub1b, its sibling. Since that's outside B-sub1's
    own subtree, it must first `share` up to its own Root (B), which then
    `reshare`s within its tree to reach B-sub1b — the two-step path remains necessary whenever
    the target isn't within the acting OU's own subtree. The folder then demonstrates the
    **cross-tree share restriction**: B-sub1 sharing directly to a *foreign* Root (Ex-A, outside
    its own tree entirely) is rejected with `SHR-1009` (`400`) by default — pushing up to its own
    Root is always allowed, but reaching someone else's Root is not. The rejection is deliberately
    generic and does not confirm anything about Ex-A's tree membership or that a config setting
    exists to lift the restriction. Lifting it requires enabling
    `resource_sharing.allow_child_ou_cross_tree_sharing` in `deployment.yaml` and restarting the
    server, a static, deployment-wide setting this collection can't flip live, so only the
    default-restricted path is exercised here.
12. **11 - Chained Delegation and Chain Integrity**: on a fresh throwaway role and a new
    grandchild organization unit (B-sub2b, under B-sub1), proves an explicit reshare
    target must be the resharing OU's own direct child (B cannot reshare straight to
    B-sub2b; B-sub1 must do it in its own call), that revoking an intermediate hop
    cascades to revoke everything delegated below it, and that excluding B-sub1 from a fresh
    `allChildren` reshare also cuts off B-sub2b even though nothing names it in the exclusion
    list, while B-sub1b (never excluded) is unaffected.
    It then demonstrates the scope between the two: an `ouIds` entry with `allChildren` set,
    so one grant from B names B-sub1 and carries its whole branch. B-sub2b is covered with no
    second hop, while B-sub1b, B's other child, stays outside it. Revoking that single grant
    removes both levels at once.
13. **12 - Scoped Admin Client Setup**: creates two client_credentials applications, one in B
    and one in B-sub1, assigns both to the **System Roles Manager** role created in `00`
    (without this, `system:roles` would list in their `inboundAuthConfig.scopes` but never actually
    appear in an issued token — RBAC still filters it), then mints two `system:roles`-scoped tokens
    (one per organization unit) plus one token requesting an unrelated scope (`system:user`), to
    demonstrate the no-`system:roles`-at-all rejection case. A third application, also in B, is
    assigned instead to the **System Roles Viewer** role and mints a `system:roles:view`-scoped
    token, to demonstrate the read-only tier in `13`.
14. **13 - API Authorization: system:roles Scope**: replaces the collection's default bearer token
    with each of the tokens from `12` in turn (via a per-request auth override) and exercises the
    Role API's own token-scope + OU restriction, independent of the sharing model exercised
    everywhere above:
    - A `system:roles` token can fully manage its own organization unit's role (`02`'s fixture),
      but is rejected — for both reads and writes — the instant it targets an organization unit
      other than its own: listing another OU (`?ouId=`), reading another OU's own role (`404`-style
      invisibility unless shared), creating a role for another OU, or naming another OU as the
      acting party on an assignment endpoint — all rejected with `ROL-1023` (OU-reach: the caller's
      scope doesn't reach that OU at all, whether or not a role exists there yet); moving or
      updating a role it doesn't own is rejected with `SHR-1007` (core-config ownership: an
      existing role's core config belongs to a different, already-established owning OU); deleting
      a role it doesn't own is rejected with `ROL-1024`, a role-specific error distinct from
      `SHR-1007` (deletion is its own resource-type-meaningful violation, not a core-config edit) —
      never silently allowed.
    - A `system:roles` token *can* still view a role that reaches it purely through a sharing grant
      from an owner outside its own OU (B viewing the main `roleId` fixture shared to it
      in `03`) — the token-scope restriction and the sharing model compose, they don't override
      each other.
    - Omitting the acting `ouId` on an assignment write defaults to the role's *owner*, not the
      caller — for a `system:roles` caller acting as a sharee, this default is outside its own OU
      scope and is rejected; it must pass its own `ouId` explicitly.
    - `GET /roles` with no `ouId` returns the same origin-tagged listing as
      `?ouId=<the token's own OU>`, not the unrestricted deployment-wide listing a `system`-scoped
      token would get.
    - A token requesting no `system`/`system:roles` scope at all is rejected before it ever reaches
      role-management logic, at the global security gate (`AUTH-4030`), not a role-specific error.
    - A `system:roles:view` token can list roles and read a role it owns, exactly like a
      `system:roles` token restricted to its own OU, but every write (`POST`/`PUT`/`DELETE
      /roles`) is rejected at the same global security gate (`AUTH-4030`) before role-management
      logic ever runs — the view/manage split is enforced at the scope-routing layer, not inside
      the role service.
15. **14 - Revoke Sharing (Unshare Cascade)**: revokes both of the main role's grants and confirms
    the affected OUs lose visibility and have their assignments cascade-deleted, while
    B-sub1's own native role is unaffected.
16. **15 - Export/Import Round-Trip**: on a fresh throwaway role owned by B, shares directly to
    B's own children (`allChildren: true`, again `stage: "share"` since the owner itself is
    issuing it) and adds an assignment as B-sub1, then calls `POST /export` and confirms the
    returned YAML includes the role's `grants:` and an `assignments:` entry carrying the sharee
    OU's own `ouId:`, not just its core config. It revokes the grant (the export already captured
    a point-in-time snapshot, so this doesn't affect it) and deletes the role, then calls
    `POST /import` with the exported content unchanged. The import recreates the role under its
    original id, replays the grant through the same `Share` call a live
    `POST /roles/{id}/grants` request would use, and reapplies B-sub1's assignment, both
    confirmed by a follow-up `GET .../grants` and `GET .../assignments?ouId=`. Cleans up its
    own grant and role at the end of the folder.
17. **16 - Cleanup**: deletes every resource created by the collection, in dependency order.

## Known Gap: `authorization_code` Is Not RBAC-Filtered

`08`'s RBAC proof only covers the `client_credentials` grant (and, by the same code path,
`token_exchange`). As of this collection, the `authorization_code` grant (interactive user login)
does **not** call the RBAC engine at token-issuance time at all: a logged-in user's token `scope`
is filtered only against the permissions registered on the target resource server, never against
that user's actual role assignments. So a user in a sharee OU assigned to a shared role would not
currently see that reflected in an `authorization_code` token's scope, for the same reason a user
assigned directly to an *owned* role wouldn't either — this is a gap in the `authorization_code`
grant handler generally, not specific to role sharing. This collection deliberately does not
include an `authorization_code` flow, since it would not be testing anything that currently works.

## Notes

- This collection creates real data (organization units, a resource server, applications, a user,
  groups, roles). Run **16 - Cleanup** at the end of each pass, or the fixed `handle`/`name` values
  used in **00 - Setup** and **12 - Scoped Admin Client Setup** (`a`, `b-sub1`,
  `demo-user`, `scoped-admin-b`, `scoped-admin-b-sub1`, `scoped-admin-b-view`, etc.) will conflict
  on the next run.
- Each request's `test` script asserts the expected status code and, where relevant, the specific
  response fields or error `code` documented in `api/role.yaml`; failures show up directly in
  Postman's test results, not just as raw response bodies.
- All requests inherit a collection-level bearer auth using `{{accessToken}}` (the `system`-scoped
  admin token), except: the two `client_credentials` token requests in `00`/`08`
  (`Get Access Token`, `Get Client Credentials Token for the App`); the four token requests in `12`
  (all authenticate via HTTP Basic auth using a scoped admin client's own credentials, not a bearer
  token, since they *are* the calls that mint one); and every request in `13`, which explicitly
  overrides the collection default with the specific `system:roles`/`system:roles:view`-scoped (or
  unrelated-scope) token under test.
