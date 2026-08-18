# ThunderID B2B Sharing — Design Document

Status: implemented, backend-only, single PR (uncommitted at time of writing). Console/frontend UI
is explicitly out of scope for this pass.

## 1. Problem Statement

ThunderID's organization units (OUs) form a tree: a Root OU (no parent) typically represents a
top-level tenant or partner organization, with child OUs beneath it. Before this work, a resource
owned by one OU (for example, a Role) was only ever visible to that OU — there was no way for an
owning organization to make a resource available to another organization's tree without physically
duplicating it.

The B2B use case this addresses: **Organization A** creates a role (a bundle of permissions) and
wants to make it available to **Organization B**, one of its partners or customers, without B
getting its own disconnected copy that immediately drifts out of sync. B, in turn, wants to hand
that role down into its own sub-organizations (regional offices, teams) — some of which may not
exist yet when B first receives the role.

This is the general shape of the problem: **owner shares a resource to a Root, the Root redistributes
it through its own subtree, and every sharee needs some parts of the resource to be *its own* (who
it assigns the role to) while other parts stay under the owner's control (the role's name and
permissions).**

## 2. Core Concepts

| Term | Meaning |
|---|---|
| **Owning OU** | The OU that created a resource and holds its authoritative core configuration. |
| **Root organization** | An OU with no parent — the boundary at which step 1 sharing lands. |
| **Sharee OU** | Any OU (a Root, or one of its descendants) that a resource has been made visible to. |
| **Core config** | The parts of a resource only the owner can ever change (for Role: `name`, `permissions`). Resolved from the owner regardless of who's asking. |
| **Templated config** | The parts of a resource each sharee OU customizes independently (for Role: `assignments` — who the role's permissions apply to). No sharee's templated data is visible to, or overwrites, any other sharee's. |
| **Grant** | A row recording that a resource has been shared or reshared to some set of OUs. |

The load-bearing idea is: **sharing never copies the resource.** A shared role is the exact same
row, same ID, everywhere. What differs per OU is only the *overlay* — a resolved view combining the
owner's core config with that OU's own templated data.

## 3. Requirements

These were captured up front, before any code was written, and shaped every decision below.

### Framework-level (resource-type-agnostic)

- A way for any future resource type to declare itself onto the sharing system without new tables
  per type.
- Two actions: **Share** (owner → one or more Roots, or all Roots — the only action that crosses
  from the owner's own subtree into a different one) and **Reshare** (any OU currently visible for
  the resource → its own subtree, including OUs created *after* the reshare call — "all future
  children" must be dynamic, not a snapshot).
- **A single-call path when the owner already sits at the top of the subtree being distributed
  into.** An owner (Root or not) redistributing to its own descendants must not be forced through
  a redundant "share to myself" step first — Reshare must be directly callable by the resource's
  own owner, with no preceding Share.
- **Delegation one hop at a time for selective (non-"all children") targeting.** An OU distributing
  to specific named children may only name its own *direct* children; reaching a grandchild
  selectively requires that child to issue its own Reshare call. "All children" is exempt from this
  — it is a single dynamic grant reaching any depth.
- **Visibility must chain, not just pattern-match.** An OU is visible only if every hop from the
  resource's tree root down to it is backed by a valid, unbroken grant (or the owner's own
  unconditional access, wherever it sits in that chain) — never merely because some row happens to
  name it. A missing or excluded link at any point must cut off everything below it.
- Templated-field editability decided at share time, as a property of the grant itself, with a
  reshare only ever able to narrow it relative to what the resharing OU itself holds.
- Caching designed in from the start, not bolted on.

### Role-specific

- Core = `name` + `permissions`, owner-only. Templated = `assignments`, per-OU.
- Per-assignee-type editability, decided per share/reshare grant.
- Listing roles for an OU must show both owned and shared roles, clearly distinguished.
- A shared role's detail view resolves core-from-owner + templated-from-caller correctly.
- **Authorization checks must include shared-role assignments** — this is the point of the whole
  feature; a permission granted via a shared role has to actually work, not just display correctly
  in the management API.

## 4. Decisions Made Up Front

Four decisions were made deliberately before implementation, in response to direct questions, and
they shaped the shape of everything else:

1. **One PR, one commit.** Not phased. This is why the change touches schema, framework, Role, and
   authz together rather than landing incrementally.
2. **Backend only.** No Console/frontend UI in this pass — every capability is exercised through
   the REST API (and, concretely, through the accompanying Postman collection) rather than a UI.
3. **Introduce OU-scoped authorization now, properly**, rather than build sharing on top of the
   pre-existing *unscoped* authorization check and leave that gap for later. This was the bigger,
   harder-to-reverse option, chosen deliberately over the smaller change.
4. **Edit the schema scripts directly.** No migration/backfill tooling — the project is pre-GA, so
   schema changes are direct edits to `backend/dbscripts/configdb/{postgres,sqlite}.sql`.

## 5. Key Design Decisions and Their Rationale

### 5.1 One ancestor walk, one bounded fetch, then an in-memory chain evaluation

"All future children" access can't be snapshotted (new child OUs must automatically inherit
access), but it also can't cost a tree walk on every permission check — that would make every
`GET /roles?ouId=` or authorization decision scale with the size of the OU tree.

The resolution: walk the caller's OU ancestor chain **once** per check, turning it into a top-down
list from the resource's tree root down to the caller. A single query then fetches every grant of
that resource type that *could* plausibly matter — an `all_roots` grant (which can apply to any
root, so it is always a candidate) or one whose target OU appears anywhere in that chain — and the
rest is evaluated in memory: walk the chain top-down, and at each step ask "is this OU the resource's
owner (unconditional), or the tree's root with an incoming Grant, or does some earlier
covered position have an `all_children` grant reaching this far, or did the immediately preceding
position explicitly Reshare to this exact OU?" One ancestor walk, one indexed fetch bounded by
chain length, and a small loop over it — never a per-grant traversal, regardless of how many grants
exist or how deep the tree is. See the architecture doc's "Visibility Resolution" section for the
concrete algorithm.

This replaced an earlier version of the same idea — a single flat SQL query matching a resolved
anchor OU — once §5.12 and §5.13 below required genuine multi-hop delegation chains to be
evaluated correctly, not just pattern-matched. Moving the evaluation into Go rather than a growing
SQL condition list also made it directly unit-testable without a database at all.

### 5.2 Generic storage, with one deliberate, documented exception

The framework tables (`RESOURCE_GRANT`, `RESOURCE_GRANT_EXCLUSION`, `RESOURCE_GRANT_EDITABLE_FIELD`,
`RESOURCE_OVERLAY`) are resource-type-agnostic — onboarding a second resource type onto sharing
requires zero new tables, only a new Go declaration.

`RESOURCE_OVERLAY` holds one row per (resource, OU), and that row's single `FIELDS` column holds
every templated field that OU overrides, as one JSON object keyed by field key. It deliberately does
not keep a row per field. A templated field set is read and written as a unit by the single OU that
owns it, so spreading it across rows bought no independent access while costing a multi-row scan on
every read and a row count that grew with however many fields a resource type declared. Collapsing
it makes a read a single-row primary key lookup, and lets a resource type add a templated field
without touching storage at all.

The trade the JSON column makes is that a write is whole-set: `SetOverlay` replaces the object, so
changing one field is a read-modify-write, and two concurrent writers to the same (resource, OU)
last-write-wins rather than each landing on its own row. That is acceptable because the writer for a
given row is always a single OU acting on a single resource, not a fan-in. If a resource type ever
does need per-field atomicity, the fix is a merging upsert (Postgres `jsonb_set`, SQLite
`json_patch`) rather than a return to row-per-field. Note also that an overlay row holding `{}` and
no overlay row at all are distinct states — "this OU overrode nothing" versus "this OU has no
overlay" — which the row-per-field shape could not express.

Role's `assignments` templated field is the one exception to using this table at all: it's stored
directly in the existing `ROLE_ASSIGNMENT` table (extended with an OU column). This is deliberate,
not a shortcut: assignments are relational (many rows per role, and rows that are themselves queried
and joined), and the authorization hot path needs a single indexed SQL predicate against a table it
already joins, not a JSON decode on every permission check. That argument holds regardless of the
overlay's internal shape, and if anything the JSON column sharpens it: the overlay is now explicitly
a whole-object read, which is exactly what an authorization predicate must not do. The generic
sharing/policy tables themselves stay entirely free of role-specific schema — this is the only place
a resource type's own storage is reused instead of the generic path, and it's confined to Role's own
pre-existing table.

Because role is currently the only registered resource type and it takes that exception,
`RESOURCE_OVERLAY` has no production reader or writer today; it is the framework's declared default
for the next resource type that brings a non-relational templated field.

### 5.3 Caching: point-invalidation by default, version-keyed only where necessary

The canonical resource record follows the codebase's existing `cache_backed_store.go` pattern:
point-delete the specific cache key on write. Editability and visibility, by contrast, are both
resolved from the grant graph and cleared wholesale on any Share/Unshare (§5.15) — there is no
separate policy row to point-invalidate any more.

The one case that can't do this is the *resolved* `(resourceType, id, OU)` view: a single owner
edit can't enumerate every sharee OU that might have it cached, without a tree fan-out. That case
uses version counters bumped in the same transaction as the write, letting stale entries simply age
out via the existing TTL/size-capped eviction rather than requiring point-precise invalidation.

### 5.4 Editability resolution order (superseded by §5.15)

The original order was `resource-level override → OU-level policy → type's compiled-in default`,
each a separately-managed setting: a per-role decision always beat an OU-wide default, which always
beat a hardcoded per-field fallback. §5.15 replaces this entirely — editability is no longer a
separately-managed setting at any level, only a property fixed on the grant that made a resource
visible to an OU in the first place. The harder design question, that survives the replacement
unchanged, was the *specificity* tie-break within a level (§5.9) — a blanket field vs. its specific
per-type siblings.

### 5.5 The acting-OU regression: a real bug, caught and root-caused

The first implementation of "which OU is this assignment call acting as?" read the caller's own OU
claim from context (`security.GetOUID(ctx)`) whenever present, falling back to the role's owning OU
only if that claim was empty.

This broke integration tests: a caller with system-wide permission (an admin session, a
registration flow) routinely manages resources **outside its own home OU** — that is not "acting as
a sharee OU", it's just an admin doing admin things. Reading the ambient claim caused ordinary,
same-tenant assignment writes to be misclassified as sharee-acting-OU writes, and their assignments
became invisible on read.

**Fix:** the acting OU became an **explicit parameter** end to end — an HTTP `?ouId=` query
parameter, threaded through every layer down to the store, with empty meaning "act as the role's
own OU" (preserving prior behavior exactly for every caller that has no sharing relationship). This
is a general principle worth stating plainly: **an ambient identity claim and an explicit
capability parameter are not interchangeable, even when they're usually the same value.** The full
120-suite integration run was re-verified green after the fix.

### 5.6 Renaming for clarity: `TIER`/`TARGET_KIND` → `SHARE_STAGE`/`TARGET_SCOPE`, `OU_ID` → `ASSIGNING_OU_ID`

Three names were flagged as insufficiently self-describing once the feature had shipped and was
being read back:

- `RESOURCE_GRANT.TIER` didn't say *what* it distinguished (the two-step share/reshare process) →
  renamed to `SHARE_STAGE`.
- `RESOURCE_GRANT.TARGET_KIND` didn't convey that it's a *breadth* concept (a single OU vs. an "all"
  scope) → renamed to `TARGET_SCOPE`.
- `ROLE_ASSIGNMENT.OU_ID` was ambiguous between "the role's owning OU" and "the OU that made this
  particular assignment" (it's the latter) → renamed to `ASSIGNING_OU_ID`.

None of these were functional bugs, but the ambiguity was real enough that a rename was worth doing
before this shipped, while it's still a single, un-merged PR with no external consumers of the old
names.

### 5.7 Exclusion policy: "share/reshare all except these"

A real B2B pattern: "share this role to every Root **except our pilot partner**" or "reshare to
every region **except the one still being onboarded**". Rather than adding new `TARGET_SCOPE`
enum values, exclusions are modeled as a separate table (`RESOURCE_GRANT_EXCLUSION`) attached to an
`all_roots`/`all_children` grant — the explicit single-target scopes (`root`/`ou`) never populate
it, since they're already precise.

The important design choice: **excluding an OU excludes its entire subtree**, not just that one
node. "Share to all Roots except Partner X" should not leave Partner X's own children still seeing
the role through some other path. This is implemented by checking a grant's exclusion list against
the *entire ancestor chain* of the OU being checked (itself plus every ancestor up to the anchor),
not just the OU's own ID — reusing the same single ancestor-walk machinery from §5.1, so exclusion
support added zero additional tree walks to the hot path. This was verified against a real SQLite
driver (not just mocks), including the specific claim that a grandchild of an excluded OU is also
excluded.

### 5.8 The owner-scoping gap in editability policy (table since removed, see §5.15)

A second real bug, this time caught by the user's own review rather than a test failure: the
OU-level editability policy table (`RESOURCE_TYPE_OU_POLICY`) was originally keyed only by
`(resourceType, sharee OU, field)` — with no owner dimension. That meant **Organization A**
setting "sharee OU X may not edit assignments" would silently also govern **Organization B**'s
roles shared to that same OU X, since both owners' policies collapsed into the same row.

This directly contradicted the requirement that "Org A decides, for its own resources, what a given
sharee org can edit" — a decision that must be scoped to the owner making it. **Fix:** added
`OWNING_OU_ID` to the table's key, and threaded an explicit `owningOUID` parameter through
`ResolveEditability`/`SetOUPolicy` and the corresponding REST endpoint (`PUT
/roles/ou-editability?owningOuId=&ouId=`). Verified with a real-database test proving two different
owners' policies for the identical sharee OU are now independent.

### 5.9 Per-assignee-type editability, with a blanket fallback field (mechanism kept, precedence question moot after §5.15)

A refinement requested after the basic editability model was in place: editability shouldn't be a
single on/off switch for "assignments" as a whole — an owner might want a sharee to be able to
assign its own groups but not its own users, for instance. So `assignments` was split into four
independently-resolvable fields, one per assignee type (`assignments.user`, `assignments.group`,
`assignments.app`, `assignments.agent`).

But requiring an owner to name all four individually every time defeats the point of a sensible
default. So a **blanket fallback field** (`assignments`, the original name, kept as one of the five
now-declared fields) was added: each per-type field declares it as a `FallbackKey`. This part is
unchanged by §5.15's redesign — a grant's `EditableFields` naming just `assignments` still covers
every type that falls back to it, and a grant wanting finer control can still name a single type's
key on its own.

What §5.15 *did* eliminate is the precedence question this section originally agonized over: with
two separately-managed layers (a per-role override and an OU-wide default), it mattered enormously
whether *level* (resource vs. OU) or *key specificity* (blanket vs. per-type) was the primary axis —
getting it backwards would let an OU-wide default silently defeat a deliberate per-role override.
Now that there is only ever one source of truth (the single grant that made the resource visible to
that OU), there is no second layer to out-rank or be out-ranked by; `FallbackKey` is a pure
membership check (`fieldKey` in `grant.EditableFields`, else `fieldKey.FallbackKey` in it) with no
precedence axis to get wrong.

This `FallbackKey` mechanism lives on the *generic* framework (`TemplatedFieldDeclaration`), not
special-cased for Role, so any future resource type onboarding multiple related templated fields
gets the same "blanket-plus-specific" capability for free.

### 5.10 REST surface: actions vs. resources

`share` and `reshare` are **actions** (`POST` only, no `GET`/`DELETE` at the same path) — they do
something, they don't represent a resource collection. Listing and revoking grants moved to their
own resource collection, `/roles/{id}/grants` (`GET`, and `DELETE .../{grantId}`). This also
happened to resolve a routing ambiguity in Go's `net/http.ServeMux` that the original combined path
required a workaround for — the cleaner REST shape and the routing fix were the same change.

### 5.11 Proving RBAC actually uses shared-role assignments

The requirements explicitly called out that authorization checks must include shared-role
assignments — this can't be taken on faith; it needed to be demonstrated end to end, against real
token issuance, not just the sharing API's own bookkeeping.

**What was verified:** an application entity, belonging to a *sharee* OU (not the role's owner),
assigned to the shared role via that sharee OU's own grant, requesting a `client_credentials`
token — and the returned token's `scope` (both the token endpoint's JSON response and the decoded
JWT payload) genuinely reflects the role's permissions. Tracing the actual Go call chain confirmed
this works today for `client_credentials` and `token_exchange` grants, because both call
`role.GetAuthorizedPermissionsByResourceServer` with the assignee's entity ID — and that lookup has
no OU-scoping applied in these grant handlers, so it always finds assignments regardless of which
OU wrote them.

**What was found and deliberately left unfixed, by the user's explicit choice:** the
`authorization_code` grant (an interactive user login) does **not** call the RBAC engine at
token-issuance time at all — a logged-in user's token scope is filtered only against the resource
server's *registered* permissions, never against that user's actual role assignments. This is a
pre-existing gap in that grant handler, not something sharing introduced or could fix on its own,
and it applies identically to owned and shared roles. Given the choice between (a) fixing it as
part of this change, (b) documenting it and testing only what works, or (c) building a test that
demonstrates the gap, the decision was **(b)**: it's called out explicitly in the accompanying
Postman collection's README as a known limitation, and no test asserts behavior that doesn't exist.

### 5.12 Generalizing Reshare: a single call when the owner is already at the top

The original two-step model (Share always precedes Reshare) had a real gap: an owning OU that is
itself a Root, distributing a role to its own children, had to Share to itself and then Reshare —
two calls to express one intent, with the first call adding nothing. More generally, the same
redundancy applied to *any* owner, Root or not, distributing to its own descendants: the owner
always has unconditional access to its own resource, so requiring it to first "share to itself"
made no sense.

**Fix:** Reshare no longer requires a prior Grant when the resharing OU *is* the resource's
own owning OU — that case is recognized directly (`resharingOUID == owningOUID`) and skips the
grant lookup entirely, persisting the new grant with an empty `ParentGrantID` (there is no parent
grant to link, exactly like a Share-stage grant). Every other resharing OU still must be currently
visible via some existing grant, found by the same chain evaluation IsShared uses.

This reframes what Share and Reshare each mean: **Share is the only operation that crosses from an
owner's own subtree into a different one** (a foreign Root's tree, or — when the owner is not
itself a Root — the owner's own Root, as a deliberate step to reach outside the owner's immediate
subtree). **Reshare is "redistribute within a subtree I already sit at the top of,"** and the
owner always sits at the top of its own subtree by definition, Root or not.

### 5.13 Delegation one hop at a time: explicit reshare targets must be immediate children

A second real B2B pattern: a Root wants to reshare to *specific* children rather than its whole
subtree, and each of those children should be able to decide independently how far to redistribute
further — to its own immediate children, to its own entire subtree, or not at all. The original
explicit-target Reshare (`TargetScopeOU`) let a Root name *any* descendant directly, at any depth,
in one call — which doesn't model delegation at all; it just lets the top of the tree micromanage
everyone below it in a single step, and does not give an intermediate OU any actual say over
whether *it* continues to redistribute the resource.

**Fix:** an explicit (non-`allChildren`) reshare target must now be the resharing OU's own direct
child, checked via the same ancestor-chain lookup already available (the target's immediate parent
must equal the resharing OU). Reaching a grandchild selectively means that child must issue its own
Reshare call naming its own children — each hop is a deliberate act by the OU that currently holds
the resource, not something an ancestor several levels up can shortcut. This composes with §5.12:
Reshare being callable by any currently-visible OU (not just Roots) is exactly what makes multi-hop
delegation chains possible in the first place. `allChildren` is deliberately exempt from this
restriction — it already models "the whole subtree, dynamically, forever" as a single relationship,
where the delegation question doesn't apply.

### 5.14 Chain integrity: visibility must not just pattern-match a target OU

Generalizing Reshare into a chain of independent hops (§5.12, §5.13) exposed a latent correctness
gap in the original visibility check. That check matched a grant against the *caller's* OU and its
resolved Root directly — it never asked whether the *intermediate* hops between the Root and the
caller were themselves actually valid. With every reshare issued directly by a Root to any
descendant, that was harmless, because there was only ever one hop to check. Once a chain can have
several independent hops, each potentially revocable or excluded on its own, a flat match becomes
wrong: a stale or data-inconsistent row naming a grandchild directly must not count if the hop from
its parent was never actually granted, and an exclusion at one level must cut off every descendant
below it, even ones reached via an otherwise-valid-looking deeper grant.

**Fix:** visibility resolution now walks the full chain from the resource's tree root down to the
target OU and requires every consecutive hop to be backed by a real grant (or the owner's own
unconditional access, wherever it sits in the chain) — an `all_children` grant at any covered
position can shortcut-cover everything below it (subject to its own exclusion list), but an
explicit hop only ever advances coverage exactly one level, from the immediately preceding
position. A gap anywhere in that chain — a missing hop, or an exclusion — cuts off visibility for
every OU below it, regardless of what any individual grant row happens to name. This was verified
with dedicated tests proving a grandchild named directly by a stale/inconsistent grant is correctly
denied when its parent's own hop was never granted, and that an exclusion partway down a chain
still cuts off a deeper, independently-named descendant.

### 5.15 Editability becomes a property of the grant itself, not a separately-managed policy

Both remaining editability layers — `RESOURCE_TYPE_OU_POLICY` (an OU-wide default an owner set via
`PUT /roles/ou-editability`) and `RESOURCE_POLICY_OVERRIDE` (a per-role override via `PUT
/roles/{id}/editability`) — were removed outright, along with both endpoints and their service
methods (`SetOUPolicy`, `SetResourcePolicyOverride`). There is no longer any way to change
editability except by revoking a grant and sharing again with a new `editableFields` list.

**Why:** editability is fundamentally a property of *how a resource was shared*, not a standing
preference an owner manages on the side, independent of any particular grant. Keeping it as a
separate policy layer meant nothing tied a sharee's editable set to the grant that actually gave it
access — which meant nothing stopped a sharee from resharing further with editability *broader*
than what it itself held. A separately-managed policy has no natural place to enforce that kind of
constraint; a property fixed on the grant that creates the access does.

**The rule this enables:** a share issued by the resource's own owning OU defaults to every declared
field (or an explicit, owner-chosen subset); a reshare issued by a sharee OU defaults to *exactly
that OU's own current editable set*, and an explicit list on a reshare must be a subset of that set
— **scope-down only, never widened** (`SHR-1008` otherwise). Because grants are immutable once
created, this check at creation time is sufficient for the whole grant's lifetime: there's no later
mutation that could let editability drift wider than what was true when the chain was built.

This also closed a real bug found while wiring the new model in: `ResolveEditability`'s replacement
needed "the single grant that governs this OU," and the existing chain-walk (`evaluateChainVisibility`,
§5.14) picked the *shallowest* covering grant when more than one matched — correct for a yes/no
visibility question (any covering grant proves visibility), but wrong once editability needed the
*most specific* one (a narrower reshare from a closer intermediate OU must win over a broader
upstream grant that also happens to reach the same descendant). Fixed by scanning the chain
deepest-ancestor-first when selecting which grant to report as "nearest."

The `OWNING_OU_ID`-scoping insight from §5.8 (one owner's policy must never leak into another
owner's resources shared to the same OU) survives implicitly: a grant is always scoped to its own
`OwningOUID` by construction, so the same leak has no way to occur any more — there's no separate
table with its own key to get wrong.

### 5.16 The Stage-labeling bug: an owner's direct distribution was mislabeled "reshare"

A second bug, found while designing §5.15 (reasoning about "what does the resharing OU's own grant
say" surfaced it): `shareToChildren` tagged **every** children-targeting grant `Stage: reshare`,
including the case where the resource's own owning OU distributes directly into its own subtree
(e.g. an owner calling `allChildren` on its own role) — a first-hop grant, the same *kind* as
root-targeting, just aimed at the owner's own children instead of a Root.

**Why it went undetected:** `evaluateChainVisibility`'s two children-targeting branches happened to
gate on `Stage == StageReshare`. Since every children-targeting grant was (incorrectly) tagged
`reshare`, visibility resolved correctly anyway — the bug was silently self-compensating for
visibility purposes. It was only ever externally visible in the audit view (`GET
.../grants`), which reported "reshare" for what was really the owner's own first share.

**Fix:** `Stage` now reflects *who issued the grant* — `share` when the resource's own owning OU
issues it (whichever target-scope mode), `reshare` only when a previously-visible non-owner OU
redistributes further — independent of target-scope mode. `evaluateChainVisibility`'s Stage gate
was removed from both children-targeting branches (kept, unchanged, at the root-targeting check,
since only an owner ever uses that mode). This is safe: the two branches already discriminate by
`TargetScope`, which is disjoint from root-targeting's scopes, so no cross-mode grant can newly
qualify by dropping the Stage check — it was already redundant there once you account for `TargetScope`.

### 5.17 `system:roles:view`: closing the last view/manage gap

Every other management-API resource (OU, User, Group, UserType, AgentType) exposes a `<resource>`
scope for full access and a `<resource>:view` scope for read-only access; Role was the one
exception, gated by a single flat `system:roles` covering create/update/delete alongside list/read.
This was a real gap, not a deliberate simplification — there was no reason a caller who should only
ever *read* role data (e.g. an audit or reporting integration) had to be handed the same scope that
also lets it create, update, or delete roles.

**Fix:** added `system:roles:view` as a genuine sibling scope, wired into the same central
`apiPermissionEntries` route table (`internal/system/security/permissions.go`) as every other
resource's view tier — `GET /roles` and `GET /roles/**` require it; `POST`/`PUT`/`DELETE` still
require full `system:roles`. Because permission matching is already hierarchical (a held scope
satisfies anything it prefixes), a `system:roles` caller automatically satisfies the new view-gated
routes too — no behavior change for existing full-access callers, no new fallback logic needed.

The OU-confinement rule (§7 of the architecture doc) is orthogonal to this and needed no change:
`role.requireOwnOUScope` doesn't care which of the two non-root scopes got the caller past the
global gate, only whether the token's own OU matches the OU the request concerns — the view/manage
distinction is decided entirely before that check ever runs.

### 5.18 `CreateRole`'s OU check moved from SHR-1007 to ROL-1023

Found via a real live `system:roles`-scoped caller creating a role in its own OU: `CreateRole`
called `sharing.RequireOwnership(ctx, roleSharingResourceType, role.OUID)`, checking the
*requested* `ouId` against the caller's own OU the same way it does for `UpdateRoleWithPermissions`
and `DeleteRole`. That reuse made sense on its face — one generic ownership check for every
core-config write — but produced a semantically wrong error for `CreateRole` specifically: `SHR-1007`
("core configuration can only be modified by the owning organization unit") describes protecting an
*existing* resource's already-established ownership from a non-owning caller. `CreateRole` has no
existing resource yet — `role.OUID` isn't a resource's owner being defended, it's the OU the caller
is attempting to *claim* as the new owner. That's the identical question `role.requireOwnOUScope`
already answers for the read/list/assignment paths ("does the caller's scope reach this OU at all"),
not a resource-ownership question.

This surfaced a real bug too, not just a wording nitpick: a separate defect (§ below) had `CreateRole`
calling `ouService.GetOrganizationUnit` without a runtime-context bypass, so a `system:roles` caller
creating a role in its *own* OU got a 500 (the OU package's own, unrelated `system:ou`/`system:ou:view`
check rejected it as Unauthorized). Diagnosing that bug required tracing exactly which check ran
first and why — a mislabeled error code at the OU-ownership gate made it harder to tell "this is an
OU-reach problem" from "this is a resource-ownership problem" at a glance, in logs and in the API
contract alike.

**Fix:** `CreateRole` now calls `role.requireOwnOUScope(ctx, role.OUID)` instead of
`sharing.RequireOwnership`, returning `ROL-1023` on mismatch. `UpdateRoleWithPermissions` and
`DeleteRole` are unchanged — they genuinely have an existing role with an established owning OU, so
`SHR-1007` still fits. This does cost some genericity: `requireOwnOUScope` lives in `internal/role`,
not in `internal/sharing`, so a future resource type reusing the sharing framework would need to
either duplicate an equivalent reach-check or accept `SHR-1007`'s ownership framing for its own
create path. That tradeoff was made deliberately (see alternatives below) rather than generalizing
the reach-check into `internal/sharing` itself, since Role is still the only resource type using this
framework today.

### 5.19 Deletion gets its own, resource-type-specific ownership error

Reported directly against a live run: deleting a role you don't own returned `SHR-1007`
("core configuration can only be modified... may create, modify, or delete its core
configuration"). Unlike §5.18's `CreateRole` case, this one genuinely has an existing resource
with an established owner, so `SHR-1007`'s ownership check is the right check — the complaint was
about the *error itself*, not the logic. "Core configuration... modified" reads oddly for a delete,
and folding create/modify/delete into one generic message loses the chance to say something
resource-type-meaningful ("this role cannot be deleted by this organization unit") for the one
operation (deletion) that most benefits from being unambiguous, especially for anyone building
against the API and branching on error `code`.

The ask was explicit: keep the underlying check generic and reusable, but let each resource type
supply its own deletion-rejection error instead of a single hardcoded one baked into
`internal/sharing`.

**Fix:** added `DeletionOwnershipError`, an optional capability a `ResourceTypeDeclaration` may
implement (checked via type assertion, mirroring `SharingHooks`), plus a new
`ServiceInterface.RequireOwnershipForDeletion` method with the identical root-bypass/own-OU-match
logic as `RequireOwnership`, except that on rejection it looks up the resource type's registered
declaration and, if it implements `DeletionOwnershipError`, returns its custom error; otherwise it
falls back to the generic `ErrorCoreConfigOwnerOnly`, unchanged for any resource type that hasn't
opted in. `internal/role`'s `roleResourceTypeDeclaration` implements it, returning a new
`ErrorRoleDeletionRestrictedToOwner` (`ROL-1024`). `DeleteRole` now calls
`RequireOwnershipForDeletion` in place of `RequireOwnership`; `UpdateRoleWithPermissions` is
unchanged (`SHR-1007` still fits a modify rejection).

This is the generic-extensibility half of what §5.18 left as a tradeoff: rather than duplicating
`requireOwnOUScope`-style logic per resource type or generalizing the *reach* check into
`internal/sharing`, the *ownership* check stays exactly as generic as it was — only the error
returned on rejection becomes resource-type-pluggable, at zero cost to a resource type that never
implements the optional interface.

### 5.20 Removed `CanGrantMembership` from role assignment add/remove: it defeated sharing's own purpose

Reported live: `POST /roles/{id}/assignments/add?ouId=<sharee>` for a role the sharee had
legitimately been shared, acting under a valid grant, still failed with `SAZ-4030` ("insufficient
privileges to grant these permissions"). The cause: `mutateAssignments`
(`internal/role/assignment_service.go`) called `sysauthz.CanGrantMembership(ctx,
PrincipalTypeRole, id)` — twice, once before `prepareAssignments` even ran and once again inside
the transaction — which requires the *acting caller's own token* to already hold every business
permission the role carries, resolved purely from the caller's stored grants, with no notion of OU,
ownership, or sharing state at all.

That requirement is incompatible with what sharing a role is *for*. An owner shares a role to a
sharee specifically so the sharee can attach its own entities/groups to it, extending the role's
reach into principals the sharee controls — not principals that already, coincidentally, hold the
exact permission set the role carries. Requiring personal coverage on every assignment call means
only a sharee that independently already has the shared role's permissions could ever use the
assignment-management capability the grant was supposed to hand it — which is close to never,
since the whole point of sharing is usually to reach OUs that *don't* already have that access. The
check also fired before `prepareAssignments`'s own ownership/sharing determination
(`IsShared`/`ResolveEditability`) ever ran, so it wasn't even deferring to that decision — it was a
structurally separate, stricter gate that could reject a call the sharing framework had already
authorized.

**Fix:** removed both `CanGrantMembership` calls from `mutateAssignments` entirely. Authorization
for "may this caller manage this role's assignments" is now decided solely by
`prepareAssignments`'s existing ownership/sharing checks — the same checks that already decide
templated-field editability, which is the correct authority for this question. This also removed
the now-dead `authzService` field/constructor parameter from `roleAssignmentService` (still used
by `roleService` for the unrelated, and still-correct, creation-time check below) and the tests
that existed solely to prove the removed guard's behavior.

This is *not* the same as removing the framework's anti-escalation posture wholesale:
`sysauthz.CanGrantPermissions` still runs in `CreateRole`, checked against the caller *defining* a
role's permission set for the first time — that check protects a genuinely different moment (can
you originate a grant of permissions you don't hold) from the one this fix addresses (can you
attach an assignee to a grant someone else already originated and explicitly shared with you).

### 5.21 Cross-tree sharing by a non-root owner is restricted by default, behind a deployment setting

Requested directly: by default, a non-root ("child") organization unit should not be able to
share a resource straight to a Root belonging to a *different* tree than its own — only to its own
tree's Root, the standard first step of push-to-own-root-then-reshare (§5.12/§5.13). A server-level
config should be able to lift that restriction for deployments that want it.

Root-targeting already required `actingOUID == owningOUID` (§4), but placed no further limit on
*which* Root(s) that owner could name — a non-root owner could already, mechanically, call
`rootOuIds: [anyForeignRoot]` or `allRoots: true` and reach an entirely unrelated tree in one hop,
with no distinction from pushing up to its own Root. That's a meaningfully bigger capability than
"push up to my own tree's top" and wasn't something every deployment should necessarily want a
non-root OU to have by default.

**The check:** `shareToRoots` resolves the owner's own tree's Root (`resolveOwnRootOUID` — itself,
if it has no ancestors, else the last entry of its ancestor chain) once per call, then: a Root owner
is always exempt (Root-to-Root distribution is ordinary, not a child reaching outside its tree); a
non-root owner targeting its own Root is always allowed (unchanged, since that's the existing
push-up pattern); a non-root owner targeting any other Root, or using `allRoots` at all, is rejected
with the new `ErrorCrossTreeShareRestricted` (`SHR-1009`) unless the setting is enabled. Default
(unset) is restricted, matching this framework's deny-by-default posture everywhere else
(scope-down-only reshare, §5.15; SHR-1007/ROL-1024's ownership checks). The check itself lives in
`internal/sharing`, not `internal/role`, since it's a property of the generic framework applicable
to any future resource type onboarded onto it — matching the "generic services" principle used
throughout this document.

**Where the setting lives — reconsidered once:** the first pass modeled it as a new `sharing`
section in `internal/serverconfig`, the runtime-mutable store `PUT /server-config/{name}` already
exposes for `cors`/`csp`/etc., following the "same pattern as the other server configs" instinct.
That required the full section-handler apparatus (`ConfigHandler.Decode`/`Validate`/`Merge`) plus a
package-level `ConfigReader`/`InitializeConfigReader` pair copied from `internal/system/csp`/`cors`
— needed there specifically because those two packages are constructed before
`internal/serverconfig` exists in the composition root, so they can't take it as a normal
constructor dependency and instead read it lazily through an interface satisfied later.
`internal/sharing` has that identical ordering problem (it's constructed, and already consumed by
`internal/role`, well before `serverconfig.Initialize`), so the same workaround was copied over
mechanically without asking whether this setting actually needed to be runtime-mutable in the first
place.

It doesn't. Unlike CORS origins or the CSP policy — things an operator plausibly wants to adjust
without a restart — this is a one-time security-posture decision for a deployment, and every other
setting of that shape in ThunderID (`tls.min_version`, `database`, `crypto`, `role.store`, ...)
lives as a plain static field in `deployment.yaml`, not the runtime store. Once reframed that way,
the whole `ConfigReader` apparatus was unnecessary complexity solving a problem this setting never
had: `internal/sharing` already reads `config.GetServerRuntime()` synchronously at construction
time (`cmd/server/servicemanager.go` calls `sharing.Initialize` well after config is loaded), so a
static field just gets threaded straight into the constructor as a plain `bool`, no interface, no
package-level mutable state, no section handler. `internal/serverconfig`'s `ConfigNameSharing` entry
and `internal/sharing/config.go` (the handler/reader pair) were removed entirely in favor of
`config.Config.ResourceSharing.AllowChildOUCrossTreeSharing`, set via `deployment.yaml`'s new
`resource_sharing:` section and changeable only by editing it and restarting.

**Update: renamed to `resource_sharing`, and the rejection message made generic.** The section was
originally named `sharing:` (`config.Config.Sharing`, field `AllowChildCrossTreeSharing`); it was
renamed to `resource_sharing:` (`config.Config.ResourceSharing`, field
`AllowChildOUCrossTreeSharing`) to read unambiguously as "sharing of resources between
organization units" rather than colliding, in a quick skim of `deployment.yaml`, with unrelated
uses of the bare word "sharing" elsewhere in the deployment config. Separately, `SHR-1009`'s
`Error`/`ErrorDescription` text originally spelled out the mechanism in full ("A non-root
organization unit may only share directly to its own tree's root; sharing to another tree's root
requires the deployment's ... config to be enabled") — this was reconsidered as leaking
implementation detail a caller has no legitimate use for: whether a given root belongs to a
foreign tree, and that a server-side toggle exists to permit reaching it, are both internal to the
deployment's organization structure and posture, not something the sharing API's error contract
should confirm or deny. The message is now a generic "Sharing is not allowed" /
"The organization unit is not allowed to share this resource to the requested target", matching
how `ErrorNotShared`/`ErrorInvalidTargetOU` already stay generic rather than explaining the exact
policy shape that was violated. The HTTP status was also confirmed as `400`, not `403`: this is a
policy-validation failure the caller can't be authorized around by holding a different permission
(unlike `ErrorCoreConfigOwnerOnly`'s `403`, where the OU boundary is the entire point), the same
reasoning `SHR-1006`/`SHR-1008` already fall under via `handleError`'s default case.

### 5.22 Export/Import and Declarative-YAML Grant Round-Tripping

**The problem:** exporting a role (declarative export, `roleExporter.GetResourceByID`) captured
core config, permissions, and the owning OU's own assignments — but not the role's grants,
nor any sharee OU's independent assignment set. Re-importing an exported role therefore silently
dropped its entire sharing state: a role shared to three OUs, each with its own assignments, came
back on re-import as an ordinary, unshared role. Declarative (file-store) roles had no
representation for a grant at all — there was no way to hand-author "this bootstrap role is
pre-shared to Root B" in YAML.

**Why replay through `Share()`, not a raw grant-column insert.** The natural-seeming alternative —
export a grant's raw columns (`ID`, `TargetScope`, `TargetOUID`, `ParentGrantID`, ...) and insert
them back verbatim on import — was considered and rejected, for two independent reasons, either one
sufficient on its own:

1. Grant `ID`s are generated via `utils.GenerateUUIDv7()` at creation time and were never meant to
   be stable identifiers preserved across an export/import round trip; only the *shape* of the
   grant graph (who issued what, to whom, with which editable fields) is meaningful, not the
   specific row IDs. Re-inserting an old grant's ID on import risks colliding with, or shadowing,
   whatever new grant lineage the target deployment builds afterward.
2. `Share()` itself has no per-caller-identity check to bypass. It validates eligibility
   structurally — is `actingOUID` the resource's owner, or already visible via an earlier grant —
   not "does the calling principal have some pre-existing right independent of the sharing graph."
   There is nothing for a "raw insert" primitive to legitimately skip past; inventing one would
   only add a second, less-validated code path alongside an operation (`Share()`) that already does
   the job correctly.

So `sharing.ServiceInterface.ExportGrants` instead returns each grant as a replayable
`(ActingOUID, SharePolicy)` pair — the exact inputs `Share()` itself takes — ordered via
`orderGrantsByDependency` so a reshare is always replayed after the grant that made its issuing OU
visible. Every one of export (round-trip verification), declarative-YAML `grants:`, and
`POST /import`'s `grants` calls the identical `Share()` method a live
`POST /roles/{id}/grants` request does; a hand-authored grant, an exported grant, and a live
API call are indistinguishable to the framework. This keeps the sharing framework's full validation
intact even for imported/replayed data, and — because `ExportGrants` and the replay path are both
generic, keyed only by `ResourceType`/`resourceID` — it costs nothing extra when a second resource
type eventually onboards onto the sharing framework.

**One flat `assignments:` list, with the assigning OU as an optional field on each entry.** The
earlier shape carried a second section, `sharedAssignments:`, holding one group per sharee OU
alongside the owner's own `assignments:`. That section is gone, and so is the `RoleSharedAssignments`
type behind it. `role.RoleAssignment` instead carries `id`, `type`, and an optional `ouId`, the OU
the assignment is recorded under (`ROLE_ASSIGNMENT.ASSIGNING_OU_ID`); a sharee OU's assignments sit
in the same list as the owner's, distinguished only by that field. The duplication the two-section
shape created was never meaningful: both sections held the same triple, one of them just encoded the
OU positionally instead of naming it. Omitting `ouId` resolves it to the assignee's own OU
(`RoleAssignmentServiceInterface.ResolveAssignmentOUIDs`, batching one
`entityService.GetEntitiesByIDs` and one `groupService.GetGroupsByIDs` lookup), which is the answer
a hand-authoring admin almost always wants: an OU assigning its own users to a role shared to it
never has to name itself.
An assignee that cannot be resolved is left blank rather than rejected there; existence is already
validated by the write path (`validateAssignmentIDs`), which reports it as an invalid assignment ID,
and duplicating that check in the resolver would only produce a second, differently-worded error for
the same condition.

**A per-assignment `ouId` forces the authorization check to become per-OU.** Deciding the acting OU
once per call was safe only while the call was the sole place an OU could come from. Now that an
assignment can name its own, `prepareAssignments` buckets the incoming assignments by effective OU
(`groupAssignmentsByOU`: the assignment's own `OUID`, else the OU resolved for the call) and runs the
complete existing gate against each bucket independently: `requireOwnOUScope`, then, for any OU that
is not the role's own, `IsShared` plus a `ResolveEditability` check per assignee type in that bucket.
`mutateAssignments` writes one store call per bucket inside the one transaction. The
`requireOwnOUScope` call in particular has to be inside the loop: applied only to the call's own
acting OU, naming a different OU on an assignment would have been a way to write outside the scope
the caller is confined to. None of this reaches the REST assignment API, whose `AssignmentRequest`
has no `ouId` at all; the defaulting and the bucketing are exercised only by the declarative and
import paths.

**Declarative (file-store) roles are no longer rejected, because there is nothing left to reject.**
The old design had `applyPendingShares` fail server startup outright when a declarative role declared
`sharedAssignments`. With no separate section in the schema, that rejection had no trigger and was
deleted. What did *not* change is the constraint underneath it: `internal/role/file_based_store.go`'s
`AddAssignments`/`RemoveAssignments` still return
`errors.New("AddAssignments is not supported in file-based store")` unconditionally, and a
declarative role's assignments still live in its YAML file rather than a mutable per-OU table. So
the lifted restriction is a matter of form, not substance. In place of the rejection,
`loadDeclarativeResources` runs `resolveLoadedAssignmentOUIDs`, which stamps each loaded assignment's
resolved OU onto the in-memory role the file store serves, falling back to the role's own OU when
the assignee cannot be resolved. Nothing is written to `ROLE_ASSIGNMENT`, and a declarative role
still cannot accumulate per-sharee assignment state; the gain is only that a declaratively-loaded
assignment now reports the same assigning OU a DB-backed one would, so a reader of either needs no
special case. `POST /import` is where `ouId` does real work: it always targets DB-backed roles (via
`roleService.CreateRole`/`UpdateRoleWithPermissions`), so `applyRoleAssignments` writes the
assignments for real. It runs strictly after `applyRoleSharing`, and the ordering is load-bearing
rather than incidental: an assignment recorded under a sharee OU only passes the `IsShared` check on
its own bucket once that OU's grant exists, so grants-then-assignments is the only order in which a
full exported document can replay.

**`importService.sharingService` as a field, not a constructor parameter.** `newImportService`
already had roughly 80 call sites across the importer package's test suite, all positional. Adding
`sharingService` as a new constructor parameter would have required updating every one of them, for
a dependency only `importRole` actually needs. Instead, `sharingService` is an unexported field on
`importService`, left unset by `newImportService` and populated after construction by the public
`Initialize(...)` wrapper (`importService.sharingService = sharingService` in `init.go`), the same
place that already wires the HTTP routes. This required changing `newImportService`'s return type
from the `ImportServiceInterface` interface to the concrete `*importService` pointer, so
`Initialize` has a concrete value whose field it can assign; Go's implicit interface satisfaction
makes this backward compatible — every existing test caller (including helper functions that
themselves return `ImportServiceInterface`, converting the concrete pointer at their own `return`
statement) still compiles unchanged. `applyRoleSharing` treats a `nil` `sharingService` as a
configuration error (`"sharingService not configured"`) rather than silently skipping grant replay,
consistent with how every other optional adapter on `importService` is guarded.

### 5.23 The organization-unit management API's own "list roles for this OU" endpoints never became sharing-aware

**The bug:** `GET /organization-units/{id}/roles` and `GET /organization-units/tree/{path...}/roles`
(`internal/ou`) reach role data through `OURoleResolver` (`internal/ou/model.go`) — a small
interface the OU package consumes so it never needs a direct import of, or query against,
`internal/role`'s tables. Its implementation, `ouRoleResolverAdapter`
(`internal/role/ou_resolver.go`), was written before sharing existed and was never revisited when
it was added: it called `roleStoreInterface.GetRoleListByOUID`/`GetRoleListCountByOUID` directly, a
plain `WHERE ROLE.OU_ID = ?` query with no join against the sharing framework at all. Meanwhile,
`internal/role`'s own `GET /roles?ouId=` (`roleService.GetRolesForOU`) was correctly updated to
additionally call `sharingService.ListSharedResourceIDs` and merge in shared roles, tagged by
`origin`. The result: two "list roles visible to this OU" surfaces existed side by side, and only
one of them actually accounted for sharing — an OU with a role shared to it would see that role via
`GET /roles?ouId=` but not via either organization-unit-management endpoint, with no error to
signal the discrepancy.

**The fix:** rather than teach `ouRoleResolverAdapter` to re-derive the owned+shared merge itself
(duplicating `GetRolesForOU`'s logic a second time, the same mistake that let this gap open in the
first place), `GetRolesForOU` was split into a thin wrapper and its actual body,
`ListRolesForOU` — a new `RoleServiceInterface` method with the identical owned+shared merge but
*no* `requireOwnOUScope` check of its own. `GetRolesForOU` keeps that check (it backs a
`system:roles`-scoped caller-facing endpoint, where the caller's own OU must match); `ListRolesForOU`
is for callers that authorize the request through a different, already-applied permission model —
exactly the OU-management endpoints, which are gated by a coarser OU-management permission scope,
not the per-OU `system:roles` model. `ouRoleResolverAdapter` now holds a `RoleServiceInterface`
(constructed from `roleService`, not the raw store) and calls `ListRolesForOU` for both its count
and list methods. `oupkg.Role` gained `OUID`/`OUHandle`/`Origin` fields (mirroring
`RoleSummaryForOUResponse`'s shape) so a caller of either OU endpoint can tell an owned role from a
shared one, and see the shared role's true owner, the same information `GET /roles?ouId=` already
exposed.

One tradeoff accepted knowingly: `OURoleResolver`'s interface keeps its existing separate
`GetRoleCountByOUID`/`GetRoleListByOUID` shape (shared by the OU package's other resource
resolvers, e.g. groups), so a single incoming request now runs the owned+shared merge twice — once
for the count, once for the page — where it previously ran a cheap, separate `SELECT COUNT(*)` for
the count. This matches `GetRolesForOU`'s own pre-existing cost shape (it already loads the entire
owned+shared set, up to `serverconst.MaxCompositeStoreRecords`, before slicing a page — there was
no cheap count path to preserve even before this fix), so it is not a new inefficiency class, just
one now paid twice per request instead of once. Reworking `OURoleResolver` to a single
count-and-list call was considered and rejected: it would mean changing an interface shared by every
other OU sub-resource listing (groups, users, ...) for a cost characteristic specific to roles.

### 5.24 Sharing one named branch whole: the `ou_subtree` scope

§5.13 made explicit reshare targets immediate-children-only, and §5.12 let an owner use
`allChildren` directly. Between them sat a gap. `allChildren` can only anchor at the OU that issued
it — the grant stores the acting OU in `TARGET_OU_ID` — so the only two things an OU could express
were "this one child, and nothing below it" (`ouIds`) and "every branch I have, to any depth"
(`allChildren`). The common middle case, *hand this one child the resource for its entire branch*,
was not expressible at all: the issuer could only name the child and then wait for that child to
redistribute in a second call the issuer does not control and cannot guarantee happens.

**Fix:** a fifth `TargetScope`, `ou_subtree`. Rather than a parallel request field, each `ouIds`
entry became an object — `{ouId, allChildren?}` — so one list carries every explicit target and each
entry says for itself how far below that child the grant reaches. An entry still names a direct
child exactly as before; setting `allChildren` additionally anchors that child's own subtree. The
same request can therefore hand one child its whole branch and another only itself.

The API shape and the stored shape deliberately differ here. `SharePolicy` keeps `OUIDs` and
`SubtreeOUIDs` as two flat lists, because they become two distinct target scopes once stored, and
`ShareRequest.ToSharePolicy` splits the one API list across them. Merging the two concepts at the
storage layer would have meant a scope value that means different things depending on a sibling
column; keeping them apart there, and together at the edge, gives each layer the shape it actually
wants. The same request field was also renamed from `ouId` to `initiatingOuId`, since `ouId`
alongside `ouIds` read as though one were the singular of the other when in fact one is the
organization unit sharing and the other the ones being shared to.

This does not weaken §5.13, which is the obvious first objection. The rule §5.13 established is
about *which OU may be named*: an issuer may only name its own direct child, so every hop is a
deliberate act by the OU that currently holds the resource. `ou_subtree` keeps that rule exactly —
what it changes is how far the grant reaches *below* the named child, and that depth is not new
authority. The named child could already have granted its whole subtree for itself with a single
`allChildren` call; `ou_subtree` lets its parent hand over precisely that, and nothing more. The
authority ceiling is unchanged; only the number of round trips is. What the intermediate OU gives up
is the ability to withhold redistribution below itself — which is the explicit intent of setting
`allChildren` on an entry, and the reason both scopes exist rather than one replacing the other.

Implementation cost was close to nil because the scope is deliberately the *union of two existing
behaviours* rather than a new traversal: in `evaluateChainVisibility` it covers its own named OU
under the same immediate-predecessor rule as an `ou` grant, and from that OU downwards it is treated
identically to an `all_children` grant anchored there, exclusions included. Both call sites became
a two-value condition instead of one. `ExcludedOUIDs` consequently works against it for free, and
`resolveGrantOUIDs` needed only to prepend the anchor, since `listSubtreeOUIDs` enumerates strictly
below its argument while here the anchor is itself a target.

Exclusions are carried on every subtree grant a single request produces, rather than partitioned per
grant. An exclusion naming an OU outside a given grant's own subtree can never appear between that
grant's anchor and a descendant of it, so it is inert there — which makes partitioning pure
bookkeeping with no behavioural difference, at the cost of an extra ancestor lookup per
(exclusion, target) pair.

## 6. Alternatives Considered and Rejected

| Alternative | Why rejected |
|---|---|
| Version-keyed caching everywhere | Unnecessary complexity where point-invalidation is structurally possible (which is nearly everywhere except the resolved cross-OU view). |
| A per-resource-type sharing/overlay table for Role assignments | Would violate "no per-resource-type sharing tables"; the `ROLE_ASSIGNMENT` reuse is scoped to Role's own pre-existing domain table, not a new invention. |
| Keeping `RESOURCE_OVERLAY` as one row per templated field (`FIELD_KEY`, `VALUE`, `UPDATED_AT`) | The per-field granularity was never used: a field set is read and written as a unit by one OU, so the extra rows bought nothing and cost a scan per read plus a row count that tracked how many fields a resource type declared. A single JSON object keyed by field key makes the read a primary key lookup. Per-field atomicity is the thing given up, recoverable with a merging upsert if a resource type ever needs it. |
| A merging upsert (`jsonb_set` / `json_patch`) so per-field writes stay atomic under the JSON column | Dialect-specific SQL and a JSON1 dependency under SQLite, to solve a contention case that cannot currently arise: a row's only writer is the single OU that owns it. Deliberately deferred until a resource type has the need. |
| Deriving the acting OU from the caller's ambient security context | Caused the §5.5 regression; a system-wide-permission caller's own OU claim is not the same concept as "acting as a sharee". |
| New `TARGET_SCOPE` enum values for exclusions (e.g. `all_roots_except`) | A separate exclusion table attached to the existing `all_roots`/`all_children` scopes is simpler and keeps the enum small; explicit single-target scopes never need exclusions in the first place. |
| Keeping a single blanket `assignments` field only (no per-type fields) | Doesn't support "let this sharee assign groups but not users"; the explicit ask was for per-type control. |
| Making per-type editability fields fall back based on which key is "more specific" rather than resource-vs-OU level | Would let an OU-wide policy silently override a per-role decision, undermining the entire point of overrides. |
| Fixing the `authorization_code` RBAC gap as part of this change | Explicitly deferred; the user chose to document the gap and test only what currently works, rather than expand scope into a second grant handler's authorization logic. |
| Letting an explicit reshare name any descendant, at any depth | Doesn't model delegation: an intermediate OU would have no say over whether the resource reaches further below it. Restricting explicit targets to immediate children forces each hop to be its own deliberate act. |
| A new schema column recording which OU issued each reshare hop | Unnecessary: because explicit hops are now restricted to immediate children, the issuer is always derivable at read time from the OU tree itself (the target's real parent), so nothing needs to be stored beyond what `RESOURCE_GRANT` already has. |
| Keeping the single flat anchor-match visibility query after generalizing Reshare | Would have silently accepted a grant naming a deep descendant directly even when an intermediate hop was missing or excluded — exactly the gap §5.14 closes. |
| Keeping `RESOURCE_TYPE_OU_POLICY`/`RESOURCE_POLICY_OVERRIDE` as a coarse default alongside per-grant `editableFields` as a finer override | Two sources of truth for the same question, with no natural place to enforce scope-down (a policy row isn't tied to any specific grant, so nothing stops it from exceeding what a reshare's own delegator actually holds). Removed entirely rather than layered. |
| Letting a reshare's `editableFields` be set freely, independent of what the resharing OU itself holds | Would let a chain of reshares escalate editability arbitrarily far past what the original owner intended to allow any single hop — exactly the privilege-escalation shape the framework's other checks (`sysauthz.CanGrantMembership`/`CanGrantPermissions`) exist to prevent elsewhere. Scope-down-only closes the same class of gap for editability. |
| Resolving editability as the intersection of every grant covering an OU, instead of just the deepest one | Unnecessary given scope-down-at-creation: a reshare's `EditableFields` is already validated to be a subset of its own delegator's set when created, so the deepest covering grant's set is transitively already the narrowest — computing an intersection across the whole chain would give the identical answer at strictly higher cost. |
| Keeping `Stage` derived from target-scope mode (root-targeting ⇒ share, children-targeting ⇒ reshare) | This is the §5.16 bug itself, not a rejected alternative considered up front — kept here as the record of what "not fixing it" would have continued to mean: an owner's own direct distribution permanently misreported as a sharee's reshare in the audit view. |
| Generalizing an OU-reach check into `internal/sharing` itself (§5.18), instead of reusing `internal/role`'s own `requireOwnOUScope` for `CreateRole` | More work for a benefit only a second resource type would need; Role is still the only consumer of this framework, so the reach-check duplication risk is hypothetical today. Revisit if/when a second resource type actually onboards. |
| Keeping `CreateRole` on `sharing.RequireOwnership`/`SHR-1007` for consistency with Update/Delete | Semantically wrong: `SHR-1007` protects an *existing* resource's established ownership, but `CreateRole` has no existing resource — `role.OUID` is a claim, not a defended fact. Consistency with the other two isn't worth an error code that describes a situation that isn't actually happening. |
| Putting the cross-tree share restriction (§5.21) in `internal/role` instead of `internal/sharing` | Would need re-deriving root-targeting mode, ancestor-chain resolution, and the config read from scratch in a resource-type-specific package, duplicating logic the generic framework already owns — and a future second resource type would get none of it for free, unlike keeping the check in `internal/sharing`. |
| Silently narrowing an `allRoots` share for a non-root, restricted owner to just its own Root, instead of rejecting the whole call | Would silently do less than the caller asked for rather than surfacing the restriction — the framework's convention elsewhere (scope-down-on-reshare, ROL-1023, SHR-1007) is always an explicit rejection with a specific error, never a quiet partial application. |
| A raw grant-insert "restore" primitive replaying exported grants' stored columns directly, instead of through `Share()` (§5.22) | Grant IDs were never meant to be stable/preserved across export/import, and `Share()` has no per-caller gate to legitimately bypass in the first place — nothing for a raw-insert path to skip that `Share()` doesn't already validate correctly. |
| Adding `sharingService` as a new `newImportService` constructor parameter (§5.22) | Would require updating ~80 existing positional test call sites for a dependency only one import path (`importRole`) needs; a post-construction field set by `Initialize` avoids the churn entirely. |
| Reworking `OURoleResolver` to a single combined count-and-list call, to avoid running the owned+shared merge twice per request (§5.23) | Would mean changing an interface shared by every other OU sub-resource listing (groups, users, ...) to fix a cost characteristic specific to roles, for a merge that already had no cheap count path before this fix. |
| Teaching `ouRoleResolverAdapter` to re-derive the owned+shared merge itself, rather than reusing `GetRolesForOU`'s logic via a new `ListRolesForOU` (§5.23) | This is exactly the mistake that let the original bug happen — duplicating the merge in a second place makes a second future divergence just as likely as the first. |

## 7. Open Items / Future Work

- **`authorization_code` grant is not RBAC-filtered.** A user's interactive login token is not
  currently scoped by their role assignments (owned or shared) at all. Fixing this would mean
  wiring the same `EvaluateAccessBatch` call the `client_credentials`/`token_exchange` handlers
  already make into the `authorization_code` handler.
- **No Console/frontend UI.** Sharing, reshare, revoke, and editability preconfiguration are only
  reachable via the REST API today.
- **Only Role is onboarded onto the sharing framework.** The framework itself is
  resource-type-agnostic by design, but no second resource type has exercised it yet.
