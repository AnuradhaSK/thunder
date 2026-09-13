# M2M Application Sharing Across Organization Units - Postman Collection

A machine-to-machine service (a bot, a CLI, a nightly reconciliation job) often has to work on behalf
of many organization units from a single registered application. Registering one application per
customer does not scale, and the service must not become visible to the delegated administrators of
the organizations it serves.

This collection exercises that: one credential pair, tokens requested against a named organization
unit, and a scope set that reflects what each of those organizations was actually granted.

```
POST /ou/{ouId}/oauth2/token     # token for a named organization unit
POST /oauth2/token               # unchanged, pre-existing behaviour
```

See [B2B_M2M_APP_SHARING_DESIGN.md](../B2B_M2M_APP_SHARING_DESIGN.md) for the design behind this,
including a sequence diagram of where client resolution, role resolution and scope filtering each
happen in a single token request.

## The three organization units involved in one token request

This is the whole design, and the collection is organized around it:

| Question | Answered by | Where it is proven |
|---|---|---|
| May this application be used here at all? | the **accessing** OU's grant of the application | folders 02 - 05 |
| What is this application entitled to? | the **application's owning** OU, via its roles and group memberships | folder 06 |
| What may the token actually carry? | the **accessing** OU's resource-server grants | folder 06 |
| Which organization is this token for? | the **accessing** OU (`ouId` / `ouName` / `ouHandle` claims) | folders 01 - 02 |

Entitlement is deliberately *not* re-resolved per accessing organization unit. The application's
roles live where the application lives; the accessing organization unit can only ever narrow the
result, never widen it.

Omitting the `/ou/{ouId}` prefix short-circuits every one of these: no grant is consulted, no scope
filtering happens, and the claims stay with the application's owner. That is what keeps existing
integrations working untouched.

## Setup

### 1. Declarative resources (required)

**Application sharing has no REST API by design**, so the three demo applications and the
organization unit tree they are granted to must come from declarative YAML. Copy these into your
deployment's declarative resource directory (`repository/resources/` in a distribution, or
`backend/cmd/server/repository/resources/` when running from source) and restart the server.

They are also checked in under
[`tests/integration/resources/declarative_resources/`](../../tests/integration/resources/declarative_resources)
if you would rather copy them from there.

#### Organization units - `organization_units/`

One document per file. `parent` names the parent's **handle**, not its id.

`m2m-root.yaml`:

```yaml
resource_type: organization_unit
id: decl-m2m-root
handle: decl-m2m-root
name: M2M Declarative Root
```

`m2m-child-a.yaml` and `m2m-child-b.yaml`, differing only in id/handle/name:

```yaml
resource_type: organization_unit
id: decl-m2m-child-a
handle: decl-m2m-child-a
name: M2M Declarative Child A
parent: decl-m2m-root
```

#### Applications - `applications/`

One document per file. The `grants:` block is the part that is declarative-only; everything else is
an ordinary application definition.

`m2m-all-ous.yaml` - granted to the entire deployment:

```yaml
resource_type: application
id: decl-m2m-all-ous
name: M2M Service (All OUs)
ouId: decl-m2m-root
type: fullstack
template: web
url: https://example.com
grants:
  - allOus: true
inboundAuthConfig:
  - type: "oauth2"
    config:
      clientId: "decl-m2m-all-ous-client"
      clientSecret: "decl-m2m-all-ous-secret"
      grantTypes:
        - "client_credentials"
      tokenEndpointAuthMethod: "client_secret_basic"
      pkceRequired: false
      publicClient: false
      token:
        accessToken:
          clientConfig:
            attributes:
              - ouId
              - ouName
              - ouHandle
```

`m2m-subtree.yaml` is the same with `id: decl-m2m-subtree`, its own `decl-m2m-subtree-client` /
`decl-m2m-subtree-secret`, and:

```yaml
grants:
  - allChildren: true
```

`m2m-selective.yaml` is the same with `id: decl-m2m-selective`, its own
`decl-m2m-selective-client` / `decl-m2m-selective-secret`, and:

```yaml
grants:
  - ouIds:
      - decl-m2m-child-a
```

The `token.accessToken.clientConfig.attributes` block is what opts the application into the
organization unit claims. Without it a token is still issued and still scoped correctly, but it
carries no `ouId`, and folders 01 and 02 cannot assert which organization it was issued for.

#### Grant shapes

The `grants:` entries take the same target-scope shape as role and resource-server grants:

| Field | Meaning |
|---|---|
| `allOus: true` | every organization unit in the deployment, any depth, including ones created later |
| `allChildren: true` | every organization unit beneath the owner, any depth, including later ones |
| `rootOuIds: [...]` | the named Root organization units |
| `ouIds: [...]` | the named organization units, which must be direct children of the granting one |
| `excludedOuIds: [...]` | carves organization units (and their subtrees) out of a blanket grant |
| `ouId:` | the organization unit performing the grant; defaults to the application's owner |

Grants are replayed through the same `Share()` a programmatic call would use, and are idempotent, so
restarting the server does not accumulate duplicates.

### 2. Roles and resource servers (no restart needed)

Roles and resource servers used by folder 06 are created through their REST APIs by the collection
itself, so nothing needs preparing. If you would rather define them declaratively:

- **Resource servers** go in `resource_servers/`, and their nested `resources:`/`actions:` are
  declared inline. Note that the declarative resource-server loader does **not** currently support a
  `grants:` block: resource-server grants are made through `POST /resource-servers/{id}/grants`, or
  through `POST /import`, which does support `grants:`.
- **Roles** go in `roles/` and do support `grants:`, plus an `assignments:` list where each entry may
  name the organization unit it is recorded under:

  ```yaml
  resource_type: role
  id: decl-m2m-role
  name: M2M Service Role
  ouId: decl-m2m-root
  permissions:
    - resourceServerId: <resource server id>
      permissions:
        - books:read
  assignments:
    - id: decl-m2m-subtree
      type: app
  ```

  An assignment that omits `ouId` is recorded under the assignee's own organization unit.

### 3. Environment

Import `environment.json`, then fill `clientId` and `clientSecret` with a client that holds the
deployment's `system` permission. That is the collection's own admin access, used for the management
calls in folders 00, 06 and 07; it is unrelated to the three M2M service credentials, which are
pinned as collection variables and need no editing.

## Collection structure

```
00 - Setup                              admin token, plus preflight checks that the
                                        declarative fixtures actually loaded (root and
                                        children are separate endpoints)
01 - Baseline                           the bare endpoint is untouched
02 - allOus Grant                       reaches every OU, including an unrelated tree
                                        it creates for the purpose
03 - allChildren Grant                  the owning subtree, any depth    (3 negatives)
04 - Selective Grant                    named OUs only                   (1 negative)
05 - Negative                           unresolvable OU, bad secret      (3 negatives)
06 - Scope Filtering                    the same credential yields different scopes
07 - Cleanup                            removes what 02, 03 and 06 created
```

Run folders in order. Folder 00 stores the admin token, and 06 stores ids that 07 deletes.

## Negative cases, and why each one is here

| Case | Expected | What it proves |
|---|---|---|
| Unrelated tree under an `allChildren` grant | `400 unauthorized_client` | a subtree grant stops at the subtree boundary |
| Another root under an `allChildren` grant | `400 unauthorized_client` | the grant is anchored at the application's own organization unit and reaches downward from there, so a different root is outside it entirely |
| Another root's *child* under an `allChildren` grant | `400 unauthorized_client` | being a child of something is not enough; it has to be a child of the owning organization unit's own subtree. Without this, "all children" could be misread as "any descendant anywhere" |
| Sibling not named by an `ouIds` grant | `400 unauthorized_client` | being next to a granted organization unit confers nothing |
| Unknown OU under a selective grant | `400 unauthorized_client` | an organization unit with no grant is refused |
| Unknown OU under an `allOus` grant | `400 unauthorized_client` | `allOus` matches every OU, so a grant check alone cannot reject an id that names none; the accessing OU is resolved *before* the grant is consulted |
| Wrong client secret | `401 invalid_client` | client authentication runs first, independent of any organization unit logic |

The refusal is `unauthorized_client`, not `invalid_client`: the client authenticated successfully and
simply has no grant for the organization unit it asked for. `invalid_client` would misdescribe it,
and would be indistinguishable from a bad secret.

## What is deliberately not covered here

- **The generic OU-targeting mechanics** (`allRoots` / `allChildren` / `ouIds`, exclusion semantics,
  one-hop delegation, cross-tree restrictions) are inherited unchanged from `internal/sharing` and
  are already proven by [role-sharing](../role-sharing). Only their application to applications is
  shown here.
Every "unrelated tree" case addresses an organization unit folder `02` creates, rather than a
declarative fixture. This matters because an *unresolvable* organization unit is refused at the
edge with the same `400 unauthorized_client` an ungranted one gets: pointing these at an id that
may not exist made the `allOus` positive fail outright, and made the `allChildren` negative pass
for entirely the wrong reason. Folder `03` then hangs a child off that same root for its second
negative, and creates a grandchild under the *owning* subtree after the grant already exists,
proving `allChildren` is evaluated against the organization unit tree at read time rather than
snapshotted, and reaches any depth. Folder `07` removes all three, deepest first.

Note also that `GET /organization-units` lists **root** organization units only. The setup
preflight is split in two for that reason: the root is checked there, and the children through
`GET /organization-units/{id}/ous`.

- **Cascade share/unshare of a resource tree** is proven by
  [resource-sharing](../resource-sharing). Folder 06 uses `excludedNodeIds` only as the means of
  building a partially granted resource server.
- **Group-derived entitlement.** Folder 06 assigns the role to the application directly. Permissions
  reached through group membership resolve through the same code path and the same owning
  organization unit, but this collection does not separately demonstrate it.
