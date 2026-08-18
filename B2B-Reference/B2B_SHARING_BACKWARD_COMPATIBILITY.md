# Role Sharing: Backward-Compatibility Analysis

This document accounts for every change the role-sharing feature (`internal/sharing`, plus the
OU-boundary enforcement it drove into `internal/role`) introduces relative to `main`
(commit `3edfbc769`, the branch point for `b2b-role-sharing-poc`), for the purpose of assessing what
an existing ThunderID deployment needs to do when upgrading to a build that includes this feature.

It complements [B2B_SHARING_ARCHITECTURE.md](B2B_SHARING_ARCHITECTURE.md) (how the feature works)
and [B2B_SHARING_DESIGN.md](B2B_SHARING_DESIGN.md) (why it was built this way); this document is
about the upgrade path, not the feature's design.

## Summary

| Area | `main` behavior | New behavior | Breaking? | Remediation |
|---|---|---|---|---|
| `ROLE_ASSIGNMENT` schema | 4-column PK, no OU column | New `ASSIGNING_OU_ID NOT NULL` column, 5-column PK, 2 new indexes | Yes — existing rows/table shape | Manual DB migration (§1) |
| `AddAssignments`/`RemoveAssignments` | Permission-coverage only, no OU check | Caller's OU must own the role, or the role must be shared to it | Yes, for non-root cross-OU callers | Document only (§2) |
| `CreateRole`/`UpdateRoleWithPermissions`/`DeleteRole` | No ownership check beyond permission coverage | Caller's OU must match the role's owning OU | Yes, for non-root cross-OU callers | Document only (§2) |
| `GetRoleWithPermissions` | No OU check | Requires ownership or an active share | Yes, for non-root cross-OU readers | Document only (§2) |
| `GET /roles` (no `ouId`) | Full deployment-wide list, one shape | Non-root callers get a scoped, differently-shaped response | Yes — silent shape change | Document only (§2) |
| RBAC / token-issuance permission resolution | Deployment-wide, no OU dimension | Same, by default (`ouID` param is opt-in and unused by every existing caller) | No | None (§3) |
| Self-registration / provisioning flow executors | Assigns default role/group unconditionally | Same — already runs under a runtime context that bypasses the new checks | No | None (§3) |
| Declarative (file-based) roles | Never supported assignment writes | Same; new OU-aware reads only affect sharing-aware callers, which didn't exist before | No | None (§3) |
| `RESOURCE_GRANT`, `RESOURCE_GRANT_EXCLUSION`, `RESOURCE_GRANT_EDITABLE_FIELD`, `RESOURCE_OVERLAY` tables | Did not exist | New tables, empty until shares are created | No | None (§4) |

## 1. `ROLE_ASSIGNMENT` schema change — the one change that needs a data migration

**What changed.** On `main`, `ROLE_ASSIGNMENT`'s primary key was
`(ROLE_ID, DEPLOYMENT_ID, ASSIGNEE_TYPE, ASSIGNEE_ID)` and the table had no organization-unit
column at all. The current schema (`backend/dbscripts/configdb/sqlite.sql:55-69`, `postgres.sql`
identical modulo `TIMESTAMPTZ` vs `TEXT` timestamp columns) adds:

```sql
ASSIGNING_OU_ID VARCHAR(36) NOT NULL,   -- new column, no default
...
PRIMARY KEY (ROLE_ID, DEPLOYMENT_ID, ASSIGNING_OU_ID, ASSIGNEE_TYPE, ASSIGNEE_ID),  -- widened

CREATE INDEX idx_role_assignment_authz ON "ROLE_ASSIGNMENT" (DEPLOYMENT_ID, ASSIGNEE_TYPE, ASSIGNEE_ID, ASSIGNING_OU_ID);
CREATE INDEX idx_role_assignment_ou ON "ROLE_ASSIGNMENT" (DEPLOYMENT_ID, ROLE_ID, ASSIGNING_OU_ID);
```

This column records which organization unit made a given assignment — the role's own owning OU for
an ordinary assignment, or a sharee OU's ID when the role has been shared to it. It has no foreign
key (deliberate — `internal/sharing`'s generic grant model has no dependency on any specific
resource type's tables), so nothing prevents an application-layer upgrade path; the constraint is
purely that the column and PK must exist before the application code that reads/writes it can run.

**Why this can't be "handled without a migration."** Every write and almost every read against this
table now references `ASSIGNING_OU_ID` unconditionally in the query text
(`backend/internal/role/store_constants.go`):

- `queryCreateRoleAssignment` (`:88-95`) — the `INSERT` column list and the `ON CONFLICT` target
  both name it.
- `queryGetRoleAssignments` (`:97-102`), `queryGetRoleAssignmentsCount` (`:104-109`),
  `queryDeleteRoleAssignmentsByIDs` (`:111-117`), `queryDeleteRoleAssignmentsByOUID` (`:134-139`),
  `queryGetAssigningOUIDs` (`:141-147`), `queryGetRoleAssignmentsByType` (`:168-175`),
  `queryGetRoleAssignmentsCountByType` (`:177-183`) — all filter on it directly.

Against an unmigrated table, every one of these fails outright with a SQL error (missing column on
SQLite/Postgres; on Postgres, `queryCreateRoleAssignment`'s `ON CONFLICT` additionally fails with
"no unique or exclusion constraint matching" until the PK itself is rebuilt) — this is a hard
failure, not a silent behavior change, so it surfaces immediately rather than corrupting data.

The only queries that treat `ouID` as optional are `buildAuthorizedPermissionsQuery` and
`buildEntityRoleIDsQuery` (`store_constants.go:277-282`, `:526-530`) — these only append the
`ASSIGNING_OU_ID` clause when a non-empty `ouID` is passed in, and (per §3) no current caller passes
one, so the RBAC/token-issuance path is unaffected either way.

**No automated migration tooling exists in ThunderID today.** The `.sql` files under
`backend/dbscripts/configdb/` are non-idempotent `CREATE TABLE` statements, not `CREATE TABLE IF NOT
EXISTS`, and there is no `schema_version` table, no `migrations/` directory, and no `ALTER TABLE`
anywhere in the repository. They are applied exactly once, only against an empty database:

- SQLite: `build.sh`'s `initialize_databases` skips a `.db` file that already exists unless invoked
  with `override=true` (packaging/release builds), in which case it *deletes and recreates* the file
  from the script — never alters an existing file in place.
- PostgreSQL: `install/local-development/docker-compose.yml` mounts these scripts into
  `/docker-entrypoint-initdb.d/`, which the official Postgres image only executes when its data
  directory is empty on first start.

So restarting an existing deployment on a binary built from this branch does **not** grant its
`ROLE_ASSIGNMENT` table the new column — it simply starts failing every one of the queries listed
above the moment a role-assignment read or write happens. This absence of any migration mechanism
is a pre-existing characteristic of the project (not introduced by this feature); role sharing is
simply the first change to require altering an existing table's shape since the schema was last
frozen.

**Recommended remediation: a manual, operator-run migration, not new migration infrastructure.**
Building a schema-versioning/migration-runner subsystem is a much larger undertaking than this one
column warrants, and would be inconsistent with how every other schema file in this project is
currently managed. The pragmatic path is a documented upgrade step an operator runs once against
their existing database before deploying the new binary. The backfill value is well-defined: every
default (non-sharing) caller already resolves `actingOUID = role.OUID`
(`resolveActingOUID`, `backend/internal/role/assignment_service.go:91-96`), so backfilling
`ASSIGNING_OU_ID` from each assignment's own role's owning OU exactly reproduces the row shape the
application already assumes wherever no sharing has happened — which is every row that exists
today, since sharing didn't exist before this feature.

Illustrative SQL (an example for an upgrade runbook, not a maintained script in this repository):

**PostgreSQL** (supports altering constraints in place):

```sql
BEGIN;

ALTER TABLE "ROLE_ASSIGNMENT" ADD COLUMN ASSIGNING_OU_ID VARCHAR(36);

UPDATE "ROLE_ASSIGNMENT" ra
SET ASSIGNING_OU_ID = r.OU_ID
FROM "ROLE" r
WHERE r.ID = ra.ROLE_ID AND r.DEPLOYMENT_ID = ra.DEPLOYMENT_ID;

-- Fails loudly if any row didn't get backfilled (e.g. an orphaned assignment
-- referencing a deleted role) — investigate before proceeding rather than
-- silently defaulting it to something.
ALTER TABLE "ROLE_ASSIGNMENT" ALTER COLUMN ASSIGNING_OU_ID SET NOT NULL;

ALTER TABLE "ROLE_ASSIGNMENT" DROP CONSTRAINT "ROLE_ASSIGNMENT_pkey";
ALTER TABLE "ROLE_ASSIGNMENT" ADD PRIMARY KEY (ROLE_ID, DEPLOYMENT_ID, ASSIGNING_OU_ID, ASSIGNEE_TYPE, ASSIGNEE_ID);

CREATE INDEX idx_role_assignment_authz ON "ROLE_ASSIGNMENT" (DEPLOYMENT_ID, ASSIGNEE_TYPE, ASSIGNEE_ID, ASSIGNING_OU_ID);
CREATE INDEX idx_role_assignment_ou ON "ROLE_ASSIGNMENT" (DEPLOYMENT_ID, ROLE_ID, ASSIGNING_OU_ID);

COMMIT;
```

**SQLite** (cannot alter or drop a primary key in place — a table rebuild is required):

```sql
BEGIN;

CREATE TABLE "ROLE_ASSIGNMENT_NEW" (
    DEPLOYMENT_ID   VARCHAR(255) NOT NULL,
    ROLE_ID         VARCHAR(36) NOT NULL,
    ASSIGNING_OU_ID VARCHAR(36) NOT NULL,
    ASSIGNEE_TYPE   VARCHAR(6)  NOT NULL CHECK (ASSIGNEE_TYPE IN ('entity', 'group')),
    ASSIGNEE_ID     VARCHAR(36) NOT NULL,
    CREATED_AT      TEXT DEFAULT (datetime('now')),
    UPDATED_AT      TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (ROLE_ID, DEPLOYMENT_ID, ASSIGNING_OU_ID, ASSIGNEE_TYPE, ASSIGNEE_ID)
);

INSERT INTO "ROLE_ASSIGNMENT_NEW"
SELECT
    ra.DEPLOYMENT_ID, ra.ROLE_ID, r.OU_ID, ra.ASSIGNEE_TYPE, ra.ASSIGNEE_ID,
    ra.CREATED_AT, ra.UPDATED_AT
FROM "ROLE_ASSIGNMENT" ra
JOIN "ROLE" r ON r.ID = ra.ROLE_ID AND r.DEPLOYMENT_ID = ra.DEPLOYMENT_ID;

-- Row-count check before dropping the old table: confirm SELECT COUNT(*) matches
-- between ROLE_ASSIGNMENT and ROLE_ASSIGNMENT_NEW; investigate any shortfall
-- (an orphaned assignment row) before proceeding.

DROP TABLE "ROLE_ASSIGNMENT";
ALTER TABLE "ROLE_ASSIGNMENT_NEW" RENAME TO "ROLE_ASSIGNMENT";

CREATE INDEX idx_role_assignment_authz ON "ROLE_ASSIGNMENT" (DEPLOYMENT_ID, ASSIGNEE_TYPE, ASSIGNEE_ID, ASSIGNING_OU_ID);
CREATE INDEX idx_role_assignment_ou ON "ROLE_ASSIGNMENT" (DEPLOYMENT_ID, ROLE_ID, ASSIGNING_OU_ID);

COMMIT;
```

Run this once, offline, before starting the new binary against an existing database. It is not a
script maintained in this repository — treat it as a starting point for whoever writes the actual
upgrade runbook, and adjust identifiers (e.g. the exact autogenerated PK constraint name on
Postgres) against the target database first.

## 2. Admin API OU-boundary tightening — intentional, document only

These changes are the feature's actual purpose (closing over-broad cross-OU access), not
incidental side effects. No code change or compatibility toggle is planned for them; they need to
be called out in release notes / an upgrade guide so operators can find and fix any integration that
depended on the old, permissive behavior.

**Role assignment writes** (`backend/internal/role/assignment_service.go`). On `main`,
`AddAssignments`/`RemoveAssignments` took no organization-unit parameter at all and were gated
solely by `sysauthz.CanGrantMembership` — a permission-coverage check with no OU dimension
whatsoever. Its `grantsNothing` fast path even let an unauthenticated caller through when the target
role conferred no permissions (the common "plain grouping role" case). Now, `prepareAssignments`
(`assignment_service.go:447-521`) buckets the request by the organization unit each assignment is
recorded under — the assignment's own `ouId` when it declares one, otherwise
`resolveActingOUID(ouID, role.OUID)` — and calls `requireOwnOUScope` on every bucket, requiring the
caller's own OU to match, unless it holds the deployment's root `system` permission or the request
runs under a runtime context. For any bucket whose OU differs from the role's own, it additionally
requires `sharingService.IsShared`/`ResolveEditability`. Only declarative YAML and `POST /import`
can produce more than one bucket: the REST assignment API's `AssignmentRequest` carries no `ouId`,
so a request there always resolves to the single acting OU, exactly as before.

**Impact:** any existing integration using a `system:roles`-scoped (not root `system`) token to add
or remove assignments on a role owned by an organization unit other than its own now fails with
**`ROL-1023`**, unless the role has been explicitly shared to its OU via
`POST /roles/{id}/grants`. Fix: either issue that caller a token with root `system`
permission, or set up the appropriate grant so it becomes a legitimate sharee.

**Role CRUD** (`backend/internal/role/service.go`). On `main`, `CreateRole` and
`UpdateRoleWithPermissions` only validated permission coverage (`CanGrantPermissions`) and that the
named OU exists — not that the caller's own OU matched it. `DeleteRole` had no ownership check at
all. Now:

- `CreateRole` (`service.go:282`) requires `requireOwnOUScope(ctx, role.OUID)` — **`ROL-1023`** on
  mismatch.
- `UpdateRoleWithPermissions` (`service.go:478-486`) requires
  `sharingService.RequireOwnership(ctx, roleSharingResourceType, existingRole.OUID)`, and if the
  update also moves the role to a different OU, against that destination OU too — **`SHR-1007`** on
  mismatch.
- `DeleteRole` (`service.go:562-565`) requires
  `sharingService.RequireOwnershipForDeletion(...)` — **`ROL-1024`** on mismatch (a role-specific
  error distinct from `SHR-1007`, since deletion isn't a core-config edit).
- All three bypass this check for a caller holding root `system` permission, matching the framework's
  existing root-bypass convention everywhere else.

**Impact:** any existing integration managing roles owned by OUs other than the caller's own,
without holding root `system` permission, now fails on create/update/delete with the codes above.
Same fix as the assignment case.

**Role reads** (`GetRoleWithPermissions`, `service.go:402`). On `main` there was no OU check at all
— any caller who could reach `GET /roles/{id}` could read any role. Now it requires
`requireOwnOUScope`, falling back to `sharingService.IsShared` for a legitimately shared role.

**`GET /roles` with no `ouId`** (`backend/internal/role/handler.go:46-63`). On `main` this always
returned the complete, unrestricted, deployment-wide role list. Now, a caller without root `system`
permission is silently rerouted to `handleRoleListForOU`, which calls the new `GetRolesForOU` and
returns a **different response shape**
(`RoleListForOUResponse`/`RoleSummaryForOUResponse`, adding `origin`/`isReadOnly` fields) scoped to
roles the caller's own OU owns or has had shared to it. This is a silent API-contract change, not an
error — any existing client parsing the old unrestricted shape for a non-root caller will observe
fewer roles and a different JSON structure after upgrade, with no error to signal it. Worth calling
out explicitly in release notes since, unlike the error-coded cases above, nothing will alert an
affected integration that its assumptions changed.

## 3. Confirmed non-breaking — no action needed

**RBAC / token-issuance permission resolution.** `GetAuthorizedPermissionsByResourceServer` and
`GetEntityRoleIDs` (`backend/internal/role/store.go`) gained a trailing `ouID` parameter, but it is
optional: `buildAuthorizedPermissionsQuery`/`buildEntityRoleIDsQuery`
(`store_constants.go:277-282`, `:526-530`) only add the `ASSIGNING_OU_ID` filter when it's
non-empty. Every current call site of the actual RBAC evaluation path
(`internal/authz/engine/rbacengine.go`, driven by `AccessEvaluationRequest.OUID`, and its callers in
`oauth/oauth2/granthandlers/*.go`, `authzen/service.go`, `flow/executor/authz_executor.go`) leaves
it unset, so this path generates the exact same SQL it did on `main` and needs no migration
awareness at all.

**Self-registration / provisioning flow executors.**
`backend/internal/flow/executor/provisioning_executor.go`'s calls into
`roleAssignmentService.AddAssigneesToRoles`/`groupService.AddMembersToGroups` run under
`ctx.Context`, which traces back to the incoming HTTP request context of the public
`POST /flow/execute` endpoint. The security middleware
(`backend/internal/system/security/service.go:190-197`, `handleAuthError`) already stamps every
request on a registered public path — including an unauthenticated self-registration flow — with
`security.WithRuntimeContext` before it reaches any executor, and `requireOwnOUScope` explicitly
bypasses runtime contexts. This is pre-existing middleware behavior (test-covered in
`security/service_test.go`), not something added by this feature, so self-registration assigning a
default role/group to a new principal is unaffected.

**Declarative (file-based) roles.** On `main`, `AddAssignments`/`RemoveAssignments` already
unconditionally returned "not supported in file-based store" errors for declarative roles — they
never supported assignment writes at all, before or after this feature. The new `ouID`-aware
restriction on the read paths (`GetRoleAssignmentsByType`, `GetAuthorizedPermissionsByResourceServer`
in `file_based_store.go`) only changes behavior for a caller passing an explicit non-owner sharee
OU, which was never a meaningful or previously-working case against a declarative role in the first
place (declarative roles have no owning-OU-vs-sharee distinction to have shared from).

## 4. New tables — additive only

`RESOURCE_GRANT`, `RESOURCE_GRANT_EXCLUSION`, `RESOURCE_GRANT_EDITABLE_FIELD`, and `RESOURCE_OVERLAY` did not
exist on `main`. They have no foreign key into or out of any pre-existing table (in particular, no
FK from `RESOURCE_GRANT` into `ROLE`/`ROLE_ASSIGNMENT` — the sharing framework is deliberately generic
and resource-type-agnostic) and start out empty on any deployment until a share is actually created.
Creating them alongside the `ROLE_ASSIGNMENT` migration in §1 needs no data transformation, no
backfill, and no special ordering beyond "run before the new binary starts."

This also covers `RESOURCE_OVERLAY`'s later reshape from one row per templated field
(`FIELD_KEY`, `VALUE`, `UPDATED_AT`) to a single `FIELDS` JSON object per (resource, OU). Because the
table is new relative to `main` and role, the only registered resource type, keeps its one templated
field in `ROLE_ASSIGNMENT` instead, the table has no writer and is provably empty on every
deployment. The reshape is therefore inert: it changes only the `CREATE TABLE` statement applied at
setup, with nothing to migrate and no deployment able to hold a row in the old shape.
