-- Table to store Entity Schemas (user/agent categories)
CREATE TABLE "ENTITY_TYPES" (
    DEPLOYMENT_ID   VARCHAR(255) NOT NULL,
    ID          VARCHAR(36) PRIMARY KEY,
    CATEGORY    VARCHAR(50) NOT NULL,
    NAME        VARCHAR(100) NOT NULL,
    OU_ID       VARCHAR(36) NOT NULL,
    ALLOW_SELF_REGISTRATION INTEGER NOT NULL DEFAULT 0,
    SCHEMA_DEF  TEXT NOT NULL,
    SYSTEM_ATTRIBUTES TEXT,
    CREATED_AT  TEXT DEFAULT (datetime('now')),
    UPDATED_AT  TEXT DEFAULT (datetime('now')),
    UNIQUE (NAME, CATEGORY, DEPLOYMENT_ID)
);

-- Composite index for deployment + category + OU-based entity type lookups
CREATE INDEX idx_entity_schemas_deployment_category_ou ON "ENTITY_TYPES" (DEPLOYMENT_ID, CATEGORY, OU_ID);

-- Table to store Roles
CREATE TABLE "ROLE" (
    DEPLOYMENT_ID           VARCHAR(255) NOT NULL,
    ID                  VARCHAR(36) PRIMARY KEY,
    OU_ID               VARCHAR(36) NOT NULL,
    NAME                VARCHAR(50) NOT NULL,
    DESCRIPTION         VARCHAR(255),
    CREATED_AT          TEXT DEFAULT (datetime('now')),
    UPDATED_AT          TEXT DEFAULT (datetime('now')),
    CONSTRAINT unique_role_ou_name UNIQUE (OU_ID, NAME, DEPLOYMENT_ID)
);

-- Composite index for deployment + OU lookups (supports UNIQUE constraint checks)
CREATE INDEX idx_role_ou_deployment ON "ROLE" (DEPLOYMENT_ID, OU_ID);

-- Table to store Role permissions
CREATE TABLE "ROLE_PERMISSION" (
    DEPLOYMENT_ID       VARCHAR(255) NOT NULL,
    ROLE_ID             VARCHAR(36) NOT NULL,
    RESOURCE_SERVER_ID  VARCHAR(36) NOT NULL,
    PERMISSION          VARCHAR(1000) NOT NULL,
    CREATED_AT          TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (ROLE_ID, DEPLOYMENT_ID, RESOURCE_SERVER_ID, PERMISSION),
    FOREIGN KEY (ROLE_ID) REFERENCES "ROLE" (ID) ON DELETE CASCADE
);

-- Index for resource server queries with deployment isolation on ROLE_PERMISSION
CREATE INDEX idx_role_permission_resource_server ON "ROLE_PERMISSION" (RESOURCE_SERVER_ID, DEPLOYMENT_ID);

-- Table to store Role assignments (to entities and groups). ASSIGNING_OU_ID is the organization
-- unit that made the assignment: the role's owning OU for its own assignments, or a sharee OU's ID
-- when the role has been shared to that OU (see RESOURCE_GRANT). This is what makes authorization
-- checks OU-scoped without a join: filtering ROLE_ASSIGNMENT by ASSIGNING_OU_ID directly answers
-- "what is this OU allowed to grant", since only a valid owner or sharee is ever permitted to write
-- a row here (enforced at the application layer, not by a foreign key, to avoid a cross-cutting
-- dependency on the sharing tables from this pre-existing table).
CREATE TABLE "ROLE_ASSIGNMENT" (
    DEPLOYMENT_ID       VARCHAR(255) NOT NULL,
    ROLE_ID         VARCHAR(36) NOT NULL,
    ASSIGNING_OU_ID VARCHAR(36) NOT NULL,
    ASSIGNEE_TYPE   VARCHAR(6)  NOT NULL CHECK (ASSIGNEE_TYPE IN ('entity', 'group')),
    ASSIGNEE_ID     VARCHAR(36) NOT NULL,
    CREATED_AT      TEXT DEFAULT (datetime('now')),
    UPDATED_AT      TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (ROLE_ID, DEPLOYMENT_ID, ASSIGNING_OU_ID, ASSIGNEE_TYPE, ASSIGNEE_ID)
);

-- Index supporting the OU-scoped authorization lookup (entity/group -> ASSIGNING_OU_ID) and
-- OU-scoped assignment cleanup on unshare.
CREATE INDEX idx_role_assignment_authz ON "ROLE_ASSIGNMENT" (DEPLOYMENT_ID, ASSIGNEE_TYPE, ASSIGNEE_ID, ASSIGNING_OU_ID);
CREATE INDEX idx_role_assignment_ou ON "ROLE_ASSIGNMENT" (DEPLOYMENT_ID, ROLE_ID, ASSIGNING_OU_ID);

-- Table capturing the resource-sharing graph. Generic across resource types: a RESOURCE_GRANT row
-- either represents step 1 (SHARE_STAGE='share', owning OU -> one or all Root OUs) or step 2
-- (SHARE_STAGE='reshare', a Root OU -> its own subtree). "All future children" reshare grants
-- (TARGET_SCOPE='all_children' or 'ou_subtree') are NOT snapshotted; TARGET_OU_ID holds the anchor
-- OU, and subtree membership is evaluated dynamically at read time by walking the target OU's
-- ancestor chain up to that anchor, so newly created child OUs are automatically in scope with no
-- backfill. 'ou_subtree' differs from 'all_children' only in that its anchor is a named direct child
-- of the issuing OU rather than the issuing OU itself, and that the anchor is itself in scope.
CREATE TABLE "RESOURCE_GRANT" (
    DEPLOYMENT_ID   VARCHAR(255) NOT NULL,
    ID              VARCHAR(36) PRIMARY KEY,
    RESOURCE_TYPE   VARCHAR(50) NOT NULL,
    RESOURCE_ID     VARCHAR(36) NOT NULL,
    OWNING_OU_ID    VARCHAR(36) NOT NULL,
    SHARE_STAGE     VARCHAR(7) NOT NULL CHECK (SHARE_STAGE IN ('share', 'reshare')),
    TARGET_SCOPE    VARCHAR(12) NOT NULL CHECK (TARGET_SCOPE IN ('all_roots', 'root', 'all_children', 'ou', 'ou_subtree')),
    TARGET_OU_ID    VARCHAR(36),
    PARENT_GRANT_ID VARCHAR(36) REFERENCES "RESOURCE_GRANT" (ID) ON DELETE CASCADE,
    CREATED_AT      TEXT DEFAULT (datetime('now')),
    UPDATED_AT      TEXT DEFAULT (datetime('now'))
);

-- Supports "list grants for a resource" and the anchored visibility lookup (resource + target).
CREATE INDEX idx_resource_grant_resource ON "RESOURCE_GRANT" (DEPLOYMENT_ID, RESOURCE_TYPE, RESOURCE_ID);
CREATE INDEX idx_resource_grant_target ON "RESOURCE_GRANT"
    (DEPLOYMENT_ID, RESOURCE_TYPE, RESOURCE_ID, TARGET_SCOPE, TARGET_OU_ID);

-- Per-grant exclusion list for "all roots"/"all children" scoped grants: an OU listed here (or any
-- descendant of it) is carved out of an otherwise-blanket share/reshare, e.g. "share to all Roots
-- except this one" or "reshare to all children except these". Meaningless (and never populated) for
-- the explicit 'root'/'ou' target scopes, since those are already precise about who is targeted.
CREATE TABLE "RESOURCE_GRANT_EXCLUSION" (
    DEPLOYMENT_ID  VARCHAR(255) NOT NULL,
    GRANT_ID       VARCHAR(36) NOT NULL REFERENCES "RESOURCE_GRANT" (ID) ON DELETE CASCADE,
    EXCLUDED_OU_ID VARCHAR(36) NOT NULL,
    PRIMARY KEY (GRANT_ID, EXCLUDED_OU_ID, DEPLOYMENT_ID)
);

-- Supports the visibility lookup's per-grant exclusion check.
CREATE INDEX idx_resource_grant_exclusion_grant ON "RESOURCE_GRANT_EXCLUSION" (DEPLOYMENT_ID, GRANT_ID);

-- Per-grant materialized set of templated field keys editable through that grant, fixed at grant
-- creation time (see Grant.EditableFields): every declared field, for a grant issued by the
-- resource's own owning OU, unless the Share call named an explicit subset; exactly the acting OU's
-- own current editable set, for a reshare, unless the call named an explicit (narrower) subset of
-- that set. Grants are immutable once created, so this table is never updated in place, only
-- inserted at creation and cascade-deleted with its grant.
CREATE TABLE "RESOURCE_GRANT_EDITABLE_FIELD" (
    DEPLOYMENT_ID VARCHAR(255) NOT NULL,
    GRANT_ID      VARCHAR(36) NOT NULL REFERENCES "RESOURCE_GRANT" (ID) ON DELETE CASCADE,
    FIELD_KEY     VARCHAR(100) NOT NULL,
    PRIMARY KEY (GRANT_ID, FIELD_KEY, DEPLOYMENT_ID)
);

-- Supports the editability lookup's per-grant field-membership check.
CREATE INDEX idx_resource_grant_editable_field_grant ON "RESOURCE_GRANT_EDITABLE_FIELD" (DEPLOYMENT_ID, GRANT_ID);

-- Generic per-(resource, OU) templated field overlay: one row per (resource, OU), holding that OU's
-- entire set of templated field overrides as a single JSON object keyed by field key. Default
-- backing store for a resource type's templated fields; a resource type may opt a specific field
-- out to a specialized store instead (e.g. role assignments use ROLE_ASSIGNMENT directly, because
-- they are relational and sit on the authorization hot path). No resource-type-specific tables are
-- added for sharing/overrides beyond this generic set.
--
-- FIELDS replaces the earlier row-per-field (FIELD_KEY, VALUE, UPDATED_AT) shape. A templated field
-- set is read and written as a whole by the one OU that owns it, so splitting it across rows bought
-- nothing; one row per (resource, OU) makes a read a single-row primary key lookup rather than a
-- scan, and keeps the row count independent of how many fields a resource type declares.
CREATE TABLE "RESOURCE_OVERLAY" (
    DEPLOYMENT_ID   VARCHAR(255) NOT NULL,
    RESOURCE_TYPE   VARCHAR(50) NOT NULL,
    RESOURCE_ID     VARCHAR(36) NOT NULL,
    OU_ID           VARCHAR(36) NOT NULL,
    FIELDS          TEXT NOT NULL,
    PRIMARY KEY (RESOURCE_TYPE, RESOURCE_ID, OU_ID, DEPLOYMENT_ID)
);

-- Table to store theme configurations.
CREATE TABLE "THEME" (
    DEPLOYMENT_ID VARCHAR(255) NOT NULL,
    ID VARCHAR(36) PRIMARY KEY,
    DISPLAY_NAME VARCHAR(255) NOT NULL,
    HANDLE VARCHAR(255) NOT NULL,
    DESCRIPTION VARCHAR(512),
    THEME TEXT NOT NULL,
    CREATED_AT TEXT DEFAULT (datetime('now')),
    UPDATED_AT TEXT DEFAULT (datetime('now')),
    UNIQUE (DEPLOYMENT_ID, HANDLE)
);

-- Index for deployment isolation on THEME
CREATE INDEX idx_theme_deployment_id ON "THEME" (DEPLOYMENT_ID);

-- Unique index for theme handle per deployment
CREATE UNIQUE INDEX idx_theme_handle_deployment ON "THEME" (HANDLE, DEPLOYMENT_ID);

-- Table to store layout configurations.
CREATE TABLE "LAYOUT" (
    DEPLOYMENT_ID VARCHAR(255) NOT NULL,
    ID VARCHAR(36) PRIMARY KEY,
    DISPLAY_NAME VARCHAR(255) NOT NULL,
    HANDLE VARCHAR(255) NOT NULL,
    DESCRIPTION VARCHAR(512),
    LAYOUT TEXT NOT NULL,
    CREATED_AT TEXT DEFAULT (datetime('now')),
    UPDATED_AT TEXT DEFAULT (datetime('now')),
    UNIQUE (DEPLOYMENT_ID, HANDLE)
);

-- Index for deployment isolation on LAYOUT
CREATE INDEX idx_layout_deployment_id ON "LAYOUT" (DEPLOYMENT_ID);

-- Unique index for layout handle per deployment
CREATE UNIQUE INDEX idx_layout_handle_deployment ON "LAYOUT" (HANDLE, DEPLOYMENT_ID);

-- Table to store inbound client configurations for an entity.
CREATE TABLE "INBOUND_CLIENT" (
    DEPLOYMENT_ID VARCHAR(255) NOT NULL,
    ENTITY_ID VARCHAR(36) PRIMARY KEY,
    AUTH_FLOW_ID VARCHAR(100) NOT NULL,
    REGISTRATION_FLOW_ID VARCHAR(100),
    IS_REGISTRATION_FLOW_ENABLED CHAR(1) DEFAULT '1',
    RECOVERY_FLOW_ID VARCHAR(100),
    IS_RECOVERY_FLOW_ENABLED CHAR(1) DEFAULT '0',
    SIGNOUT_FLOW_ID VARCHAR(100),
    THEME_ID VARCHAR(36),
    LAYOUT_ID VARCHAR(36),
    PROPERTIES TEXT
);

-- Index for efficient lookups by theme.
CREATE INDEX idx_inbound_client_theme_id ON "INBOUND_CLIENT"(THEME_ID);

-- Index for efficient lookups by layout.
CREATE INDEX idx_inbound_client_layout_id ON "INBOUND_CLIENT"(LAYOUT_ID);

-- Table to store OAuth inbound profile for an entity.
CREATE TABLE "OAUTH_INBOUND_PROFILE" (
    DEPLOYMENT_ID VARCHAR(255) NOT NULL,
    ENTITY_ID VARCHAR(36) NOT NULL,
    OAUTH_CONFIG TEXT,
    PRIMARY KEY (ENTITY_ID, DEPLOYMENT_ID),
    FOREIGN KEY (ENTITY_ID) REFERENCES "INBOUND_CLIENT"(ENTITY_ID) ON DELETE CASCADE
);

-- Table to store identity providers.
CREATE TABLE "IDP" (
    DEPLOYMENT_ID VARCHAR(255) NOT NULL,
    ID VARCHAR(36) PRIMARY KEY,
    NAME VARCHAR(255) NOT NULL,
    DESCRIPTION VARCHAR(500),
    TYPE VARCHAR(20) NOT NULL,
    PROPERTIES TEXT,
    ATTRIBUTE_CONFIGURATION TEXT,
    CREATED_AT TEXT DEFAULT (datetime('now')),
    UPDATED_AT TEXT DEFAULT (datetime('now'))
);

-- Composite index for name-based IDP lookups
CREATE INDEX idx_idp_name_deployment ON "IDP" (DEPLOYMENT_ID, NAME);

-- Expression index for issuer-based IDP lookups
CREATE INDEX idx_idp_issuer ON "IDP" (DEPLOYMENT_ID, json_extract(PROPERTIES, '$.issuer.value'));

-- Table to store notification senders.
CREATE TABLE "NOTIFICATION_SENDER" (
    DEPLOYMENT_ID VARCHAR(255) NOT NULL,
    NAME VARCHAR(255) NOT NULL,
    ID VARCHAR(36) PRIMARY KEY,
    DESCRIPTION VARCHAR(500),
    TYPE VARCHAR(20) NOT NULL,
    PROVIDER VARCHAR(20) NOT NULL,
    PROPERTIES TEXT,
    CREATED_AT TEXT DEFAULT (datetime('now')),
    UPDATED_AT TEXT DEFAULT (datetime('now'))
);

-- Composite index for name-based notification sender lookups
CREATE INDEX idx_notification_sender_name_deployment ON "NOTIFICATION_SENDER" (DEPLOYMENT_ID, NAME);

-- Table to store certificates associated with various entities.
CREATE TABLE "CERTIFICATE" (
    DEPLOYMENT_ID VARCHAR(255) NOT NULL,
    ID VARCHAR(36) PRIMARY KEY,
    REF_TYPE VARCHAR(20) NOT NULL,
    REF_ID VARCHAR(36) NOT NULL,
    TYPE VARCHAR(20) NOT NULL,
    VALUE TEXT NOT NULL,
    CREATED_AT TEXT DEFAULT (datetime('now')),
    UPDATED_AT TEXT DEFAULT (datetime('now')),
    UNIQUE (REF_TYPE, REF_ID, DEPLOYMENT_ID)
);

-- Table to store resource servers.
CREATE TABLE "RESOURCE_SERVER" (
    DEPLOYMENT_ID VARCHAR(255) NOT NULL,
    ID VARCHAR(36) PRIMARY KEY,
    OU_ID VARCHAR(36) NOT NULL,
    NAME VARCHAR(100) NOT NULL,
    DESCRIPTION TEXT,
    IDENTIFIER VARCHAR(2048) NOT NULL,
    TYPE VARCHAR(20) CHECK (TYPE IS NULL OR TYPE IN ('API', 'MCP', 'CUSTOM')),
    PROPERTIES TEXT,
    CREATED_AT TEXT DEFAULT (datetime('now')),
    UPDATED_AT TEXT DEFAULT (datetime('now')),
    UNIQUE (OU_ID, NAME, DEPLOYMENT_ID)
);

-- Composite index for name-based resource server lookups
CREATE INDEX idx_resource_server_name_deployment ON "RESOURCE_SERVER" (DEPLOYMENT_ID, NAME);

-- Unique constraint: Resource server identifier must be unique per deployment
CREATE UNIQUE INDEX uq_resource_server_identifier
    ON "RESOURCE_SERVER"(IDENTIFIER, DEPLOYMENT_ID);

-- Table to store resources within resource servers.
CREATE TABLE "RESOURCE" (
    DEPLOYMENT_ID VARCHAR(255) NOT NULL,
    ID VARCHAR(36) PRIMARY KEY,
    RESOURCE_SERVER_ID VARCHAR(36) NOT NULL,
    PARENT_RESOURCE_ID VARCHAR(36),
    NAME VARCHAR(100) NOT NULL,
    HANDLE VARCHAR(100) NOT NULL,
    DESCRIPTION TEXT,
    PROPERTIES TEXT,
    PERMISSION VARCHAR(1000) NOT NULL,
    CREATED_AT TEXT DEFAULT (datetime('now')),
    UPDATED_AT TEXT DEFAULT (datetime('now')),

    FOREIGN KEY (RESOURCE_SERVER_ID)
        REFERENCES "RESOURCE_SERVER"(ID)
        ON DELETE RESTRICT
        ON UPDATE CASCADE,
    FOREIGN KEY (PARENT_RESOURCE_ID)
        REFERENCES "RESOURCE"(ID)
        ON DELETE RESTRICT
        ON UPDATE CASCADE
);

-- Composite index for resource server + deployment queries (list, count, and handle checks)
CREATE INDEX idx_resource_server_deployment ON "RESOURCE" (RESOURCE_SERVER_ID, DEPLOYMENT_ID);

-- Unique constraint: Resource handle must be unique under the same parent per deployment
CREATE UNIQUE INDEX uq_resource_handle_with_parent
    ON "RESOURCE"(RESOURCE_SERVER_ID, PARENT_RESOURCE_ID, HANDLE, DEPLOYMENT_ID)
    WHERE PARENT_RESOURCE_ID IS NOT NULL;

-- Unique constraint: Root-level resource handles must be unique per resource server per deployment
CREATE UNIQUE INDEX uq_resource_handle_null_parent
    ON "RESOURCE"(RESOURCE_SERVER_ID, HANDLE, DEPLOYMENT_ID)
    WHERE PARENT_RESOURCE_ID IS NULL;

-- Table to store actions at resource server or resource level.
CREATE TABLE "ACTION" (
    DEPLOYMENT_ID VARCHAR(255) NOT NULL,
    ID VARCHAR(36) PRIMARY KEY,
    RESOURCE_SERVER_ID VARCHAR(36) NOT NULL,
    RESOURCE_ID VARCHAR(36),
    NAME VARCHAR(100) NOT NULL,
    HANDLE VARCHAR(100) NOT NULL,
    DESCRIPTION TEXT,
    PERMISSION VARCHAR(1000) NOT NULL,
    PROPERTIES TEXT,
    CREATED_AT TEXT DEFAULT (datetime('now')),
    UPDATED_AT TEXT DEFAULT (datetime('now')),

    FOREIGN KEY (RESOURCE_SERVER_ID)
        REFERENCES "RESOURCE_SERVER"(ID)
        ON DELETE RESTRICT
        ON UPDATE CASCADE,
    FOREIGN KEY (RESOURCE_ID)
        REFERENCES "RESOURCE"(ID)
        ON DELETE RESTRICT
        ON UPDATE CASCADE
);

-- Composite index for action list/count queries filtered by resource server + deployment + resource
CREATE INDEX idx_action_server_deployment ON "ACTION" (RESOURCE_SERVER_ID, DEPLOYMENT_ID, RESOURCE_ID);

-- Unique constraint: Server-level action handles must be unique per resource server per deployment
CREATE UNIQUE INDEX uq_action_server_handle
    ON "ACTION"(RESOURCE_SERVER_ID, HANDLE, DEPLOYMENT_ID)
    WHERE RESOURCE_ID IS NULL;

-- Unique constraint: Resource-level action handles must be unique per resource per deployment
CREATE UNIQUE INDEX uq_action_resource_handle
    ON "ACTION"(RESOURCE_ID, HANDLE, DEPLOYMENT_ID)
    WHERE RESOURCE_ID IS NOT NULL;

-- Table to store active flow definitions
CREATE TABLE "FLOW" (
    DEPLOYMENT_ID VARCHAR(255) NOT NULL,
    ID VARCHAR(36) PRIMARY KEY,
    HANDLE VARCHAR(100) NOT NULL,
    NAME VARCHAR(100) NOT NULL,
    FLOW_TYPE VARCHAR(50) NOT NULL,
    ACTIVE_VERSION INTEGER NOT NULL,
    CREATED_AT TEXT DEFAULT (datetime('now')),
    UPDATED_AT TEXT DEFAULT (datetime('now')),
    UNIQUE (HANDLE, FLOW_TYPE, DEPLOYMENT_ID)
);

-- Composite index for flow type + deployment queries
CREATE INDEX idx_flow_type_deployment ON "FLOW" (DEPLOYMENT_ID, FLOW_TYPE);

-- Table to store flow version history
CREATE TABLE "FLOW_VERSION" (
    DEPLOYMENT_ID VARCHAR(255) NOT NULL,
    FLOW_ID VARCHAR(36) NOT NULL,
    VERSION INTEGER NOT NULL,
    NODES TEXT NOT NULL,
    INTERCEPTORS TEXT,
    CREATED_AT TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (FLOW_ID, VERSION, DEPLOYMENT_ID),
    FOREIGN KEY (FLOW_ID)
        REFERENCES "FLOW"(ID)
        ON DELETE CASCADE
);

-- Table to store i18n translations
CREATE TABLE "TRANSLATION" (
    DEPLOYMENT_ID   VARCHAR(255) NOT NULL,
    MESSAGE_KEY     VARCHAR(255) NOT NULL,
    LANGUAGE_CODE   VARCHAR(10) NOT NULL,
    NAMESPACE       VARCHAR(50) NOT NULL DEFAULT 'default',
    VALUE           TEXT NOT NULL,
    CREATED_AT      TEXT DEFAULT (datetime('now')),
    UPDATED_AT      TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (DEPLOYMENT_ID, NAMESPACE, MESSAGE_KEY, LANGUAGE_CODE)
);

-- Index for efficient language and namespace combination lookups
CREATE INDEX idx_translation_lang_namespace ON "TRANSLATION" (DEPLOYMENT_ID, LANGUAGE_CODE, NAMESPACE);

-- Table to store OpenID4VP presentation definitions.
CREATE TABLE "PRESENTATION_DEFINITION" (
    DEPLOYMENT_ID VARCHAR(255) NOT NULL,
    ID VARCHAR(36) PRIMARY KEY,
    HANDLE VARCHAR(255) NOT NULL,
    OU_ID VARCHAR(36) NOT NULL,
    NAME VARCHAR(255),
    DESCRIPTION VARCHAR(255),
    VCT VARCHAR(512) NOT NULL,
    FORMAT VARCHAR(64) NOT NULL DEFAULT 'dc+sd-jwt',
    CLAIMS TEXT,
    ENFORCE_TRUSTED_ISSUER INTEGER,
    TRUSTED_AUTHORITIES TEXT,
    CREATED_AT TEXT DEFAULT (datetime('now')),
    UPDATED_AT TEXT DEFAULT (datetime('now'))
);

-- Each presentation definition handle is unique per deployment.
CREATE UNIQUE INDEX idx_openid4vp_pd_handle ON "PRESENTATION_DEFINITION" (DEPLOYMENT_ID, HANDLE);

-- Table to store OpenID4VCI credential configurations.
CREATE TABLE "CREDENTIAL_CONFIGURATION" (
    DEPLOYMENT_ID VARCHAR(255) NOT NULL,
    ID VARCHAR(36) PRIMARY KEY,
    HANDLE VARCHAR(255) NOT NULL,
    OU_ID VARCHAR(36) NOT NULL,
    NAME VARCHAR(255),
    DESCRIPTION VARCHAR(255),
    FORMAT VARCHAR(64) NOT NULL DEFAULT 'dc+sd-jwt',
    VCT VARCHAR(512) NOT NULL,
    CLAIMS TEXT,
    DISPLAY TEXT,
    VALIDITY_SECONDS INTEGER,
    CREATED_AT TEXT DEFAULT (datetime('now')),
    UPDATED_AT TEXT DEFAULT (datetime('now'))
);

-- Each credential configuration handle is unique per deployment.
CREATE UNIQUE INDEX idx_openid4vci_cc_handle ON "CREDENTIAL_CONFIGURATION" (DEPLOYMENT_ID, HANDLE);

-- Table to store server-wide configuration
CREATE TABLE "SERVER_CONFIG" (
    DEPLOYMENT_ID VARCHAR(255) NOT NULL,
    NAME          VARCHAR(255) NOT NULL,
    VALUE         TEXT         NOT NULL,
    CREATED_AT    TEXT         DEFAULT (datetime('now')),
    UPDATED_AT    TEXT         DEFAULT (datetime('now')),
    PRIMARY KEY (DEPLOYMENT_ID, NAME)
);
