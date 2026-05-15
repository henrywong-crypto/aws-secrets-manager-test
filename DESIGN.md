# AWS Secrets Portal — Minimal Design

Single-purpose web app: engineer submits a secret-value change request,
a different person approves, the app writes the value to AWS Secrets
Manager. Plaintext value never persisted.

Web stack (axum, Postgres, Cognito session, `axum_csrf`, `format!` HTML,
`AppError(StatusCode, String)`) mirrors `~/gateway`. Rust conventions
follow `~/chat-test3/CLAUDE2.md`.

---

## 1. Invariants

1. Plaintext value lives only in RAM during submit and L2-approve
   handlers. DB stores **KMS ciphertext only**.
2. **Two levels of approval** required to push a value to AWS:
   - **L1** = any member of the secret's `portal:l1-approver-group` tag
     (see §5), excluding the requester.
   - **L2** = any member of the config'd `l2_approver_group`,
     excluding the requester and the L1 approver.
   Either level may also REJECT, which is terminal.
3. The KMS decrypt + `PutSecretValue` happen **only on L2 approve**.
   L1 approve advances the state machine but does not touch AWS.
4. All approver-identity rules (`approver != requester`, `L2 != L1`)
   are enforced by `request_approvals` cross-row checks in the
   transaction **and** re-checked in the handlers.
5. Requester ∈ secret's `portal:allowed-group` tag. L1 ∈ secret's
   `portal:l1-approver-group` tag. L2 ∈ `l2_approver_group` from config.
   All three are Cognito groups read from the ID token.

Out of scope for v1: rotation, reads, N-of-M, admin UI, cancel, JSON API.

---

## 2. Rust conventions

These are project-wide rules, adopted from `~/chat-test3/CLAUDE2.md` and
specialised where this project needs more.

### 2.1 Crates

| Concern           | Choice                                                      |
|-------------------|-------------------------------------------------------------|
| Error propagation | `anyhow`                                                    |
| Date & time       | `chrono`                                                    |
| HTTP framework    | `axum` 0.8                                                  |
| Async runtime     | `tokio` (features = `["full"]`)                             |
| Database          | `sqlx` 0.8 (Postgres, `tls-rustls`, `macros`, `uuid`, `chrono`) |
| Migrations        | `sqlx::migrate!()` at boot                                  |
| Sessions          | `tower-sessions` + `tower-sessions-sqlx-store` (Postgres)   |
| CSRF              | `axum_csrf` (one-shot `authenticity_token` pattern)         |
| Cognito           | gateway's shared `handlers` / `jwks` / `validation` git crates |
| AWS SDK           | `aws-config`, `aws-sdk-kms`, `aws-sdk-secretsmanager` v1    |
| Config loader     | `config` 0.15 (File + Environment)                          |
| Logging           | `tracing`, `tracing-subscriber`                             |
| Serialization     | `serde`, `serde_json`                                       |
| IDs               | `uuid` (v4, `serde`)                                        |
| Encoding          | `base64`                                                    |

No `thiserror`, no `zeroize`, no `reqwest` in v1.

### 2.2 Error handling

Propagate errors with `?` and add context via `.context("...")`. Never
swallow an error by substituting a default — defaults hide bugs.

```rust
// Good — fail with context
let user_id = users::get_user_id(pool, &email)
    .await
    .context("lookup user_id by email")?;

// Bad — silently substitute a default
let user_id = users::get_user_id(pool, &email).await.unwrap_or_default();
```

The following patterns are forbidden anywhere in this codebase:

- `.unwrap_or(…)` / `.unwrap_or_default()` / `.unwrap_or_else(…)` on a
  `Result`. (On `Option` they're fine when `None` is a legitimate value.)
- `.ok()` to drop an error.
- `let _ = fallible_call().await;`.
- `if let Ok(x) = …` with no `else` arm.
- Catch-all `Err(_) => { /* nothing */ }`.

### `#[serde(default)]` — conditional, not banned

Allowed:

- Genuinely optional fields (feature flags, additive settings added in a
  later version that old configs don't know about).
- Collections that may be absent (`Vec<T>`, `HashMap<_,_>`) where an
  empty collection is a valid state.

Forbidden:

- **Required** configuration fields — anything the app cannot function
  without (database URL, AWS region, KMS key ARN, Cognito client id,
  CSRF key, etc.). A missing or misspelled required key must fail boot,
  not be silently replaced with a plausible default.

In practice: every field in `AppConfig` whose absence would produce a
broken deployment has **no** default. Every field whose absence is a
genuine "leave it off" has one.

Use `Option` only when the absence of a value is part of normal logic
(e.g. `get_by_name` returning `None` because the name isn't in the
allow-list). Use `Result` for anything that can fail due to I/O, missing
data, or invalid input.

**Never log error details in `warn!` / `error!` messages.** Internal
errors can leak sensitive information (query fragments, SDK debug output,
in this project potentially the secret name or ciphertext). Log a static
description of what failed; discard the error.

```rust
// Good — static message, error discarded
if let Err(_) = notify_pending_approvers(...).await {
    warn!("failed to notify approvers");
}

// Bad — leaks internal details
if let Err(e) = notify_pending_approvers(...).await {
    warn!("failed to notify approvers: {e}");
}
```

This tightens gateway's `myerrors`, which does
`tracing::error!("internal error: {err:#}")`. We do not copy that. See
§11 for how `AppError` logs without interpolating the error.

### 2.3 Keyword conflicts

When a field collides with a Rust keyword, use a trailing underscore.
Don't use `r#type` and don't prefix-rename.

```rust
// Good
#[serde(rename = "type")]
pub type_: String,
```

### 2.4 Imports

All imports at the top of the file, in two sections separated by one
blank line: external first, then `crate::`. No blank line within a
section. No `super::` outside `#[cfg(test)] mod tests`. Combine
`crate::` imports that share a top-level module into one nested `use`.

```rust
use std::net::SocketAddr;
use anyhow::{Context, Result};
use axum::extract::State;
use sqlx::PgPool;

use crate::aws::{kms_decrypt, kms_encrypt, put_secret_value};
use crate::handlers::mod::{esc, page};
```

Exceptions allowed inline (no `use`): `serde_json::{to_string, from_slice, from_str, to_vec, Value, json!}`,
`tracing_subscriber::fmt::init()`, `tracing_subscriber::EnvFilter`,
`std::env::var`, `aws_config::load_defaults`, associated type
definitions (`type Error = anyhow::Error;`).

### 2.5 Function naming

Every function is `verb_noun`. The verb describes the action, the noun
matches the return type or the thing acted on.

```rust
fn get_request(id: Uuid) -> Option<Request>;
fn list_pending_requests(pool: &PgPool) -> Vec<Request>;
fn create_request(params: &NewRequestParams) -> Result<Uuid>;
fn mark_approved(pool: &PgPool, id: Uuid, ...) -> Result<Request>;
fn render_request_detail(request: &Request) -> String;
fn encrypt_secret_value(plaintext: &str) -> Result<String>;
```

When a non-SDK async function would otherwise run without any upper
time bound (e.g. reading an unbounded channel, waiting on a future with
no inherent limit), the unbounded variant ends in `_unbounded` and the
bounded counterpart wraps it in `tokio::time::timeout`.

**AWS SDK calls do not get this treatment.** The SDK exposes
`aws_config::timeout::TimeoutConfig` but `load_defaults(...)` only
sets `connect_timeout = 3.1s` — `read_timeout`,
`operation_timeout`, and `operation_attempt_timeout` are unset. v1
accepts that: we inherit SDK defaults. If a hung call becomes a
problem, the fix is one-time client config at boot, not per-call
wrappers.

### 2.6 Variable naming

Variables are named after their type in `snake_case`. Primitives and
generic wrappers get a descriptive domain noun.

```rust
let request: Request = get_request(id)?;
let allowed_secrets: Vec<AllowedSecret> = list_for_groups(pool, &groups).await?;
let approver_note: &str = form.note.trim();
let status_label: &str = match request.status { ... };
```

No `result`, `data`, `val`, `n`.

### 2.7 Function boundaries

One level of abstraction per function. Distinct sequential phases or
repeated structural blocks go into their own named functions. The submit
and decision handlers in §8 are each a straight sequence of calls with
no inlined loops or nested logic.

### 2.8 Function arguments

Prefer `&` references; avoid owned parameters. Avoid `&mut` parameters
— return a new value. `mut` is only for local variables. Handlers take
`State<AppState>` by value because axum requires it; everything else
follows the rule.

### 2.9 Return values

Never return a tuple to bundle multiple values. Split into focused
functions instead. The single exception in this design is the SQLx
`query_as!` pattern that materialises one row into one struct — always
a named struct, never a bare tuple.

### 2.10 Type safety (newtypes)

Raw `String` is opaque — the compiler can't catch a `secret_name`
passed where a `group` is expected. Use newtypes for values that carry
domain meaning. `SecretName` and `CognitoGroup` are defined in
`myhandlers` (used across both `server::aws` and the handlers);
request-specific newtypes live in `secret_requests`:

```rust
// myhandlers
pub struct SecretName(pub String);      // max 512, matches AWS SM limits
pub struct CognitoGroup(pub String);

// secret_requests
pub struct SecretRequestId(pub Uuid);
pub struct EncryptedValueB64(pub String);
pub struct Reason(pub String);          // 1..=2000 chars, validated at construction
pub enum Status { PendingL1, PendingL2, Approved, Rejected }
pub enum ApprovalLevel { L1, L2 }
pub enum Decision { Approved, Rejected }
```

Plain `String` is reserved for values with no domain meaning (template
bodies, form fields before validation). Emails stay as plain `String`
to match gateway's `users` crate.

### 2.11 Versioning & edition

All crate versions in `Cargo.toml` use 3-part semver (`0.1.0`). Rust
edition is `2024`. Toolchain pinned in `rust-toolchain.toml`.

### 2.12 Project-specific rules

- **Domain crates are axum-free.** `users` and `secret_requests` export
  `async fn`s taking `&PgPool` (or `&mut Transaction<'_, Postgres>`) and
  return `anyhow::Result<T>`. No `IntoResponse`, no `extract::State`.
  This matches gateway's `apikeys` / `users` split.
- **`sqlx::query!` / `query_as!` everywhere.** Zero string-built SQL,
  zero runtime-checked queries. Offline cache in `.sqlx/` committed.
- **Transactions are opened and closed in the same function** (a domain
  crate function). Handlers never hold a `Transaction`.
- **Plaintext lives in a `String` on the handler stack and nowhere
  else.** Not on `AppState`, not in a struct field, not in a log line.
  Forbidden identifier list for log macro arguments: `plaintext`,
  `secret_value`. CI greps for these.
- **`AppState` is cheap to clone:** `Arc<PgPool>` + AWS SDK clients
  (already `Clone`) + small `String`s.
- **No `panic!` / `unwrap` / `expect` on runtime paths**, including
  boot. `main` returns `anyhow::Result<()>`. Clippy in CI with
  `clippy::unwrap_used`, `clippy::expect_used` (outside tests),
  `clippy::panic`, `clippy::todo`, `clippy::dbg_macro` denied.

---

## 3. Layout

Cargo workspace with **top-level crates**. Nine crates: shared error,
shared app-state, four data-access domain crates, two AWS SDK wrappers,
binary.

```
aws-secrets-portal/
├── Cargo.toml                 # [workspace] members = [...]
├── rust-toolchain.toml
├── .gitignore
├── .sqlx/                     # committed offline cache
├── migrations/
│   ├── 0_extensions.sql
│   ├── 1_users.sql
│   ├── 2_secret_requests.sql
│   ├── 3_request_approvals.sql
│   ├── 4_groups.sql
│   ├── 5_user_group_memberships.sql
│   └── 6_prefix_policies.sql
│
├── myerrors/                  # AppError + IntoResponse
├── myhandlers/                # AppState
├── users/                     # users table helpers
├── groups/                    # groups + memberships helpers
├── prefix_policies/           # prefix_policies helpers (longest-prefix lookup)
├── secret_requests/           # secret_requests + request_approvals
├── aws-secrets-manager/       # thin wrapper over aws-sdk-secretsmanager
├── aws-kms/                   # thin wrapper over aws-sdk-kms
└── server/                    # the binary
    ├── Cargo.toml
    └── src/
        ├── main.rs
        ├── config.rs          # AppConfig + load_config (deployment fields only)
        ├── csrf.rs
        ├── database.rs
        └── handlers/
```

Workspace `Cargo.toml`:

```toml
[workspace]
resolver = "2"
members  = [
    "myerrors", "myhandlers", "users", "groups",
    "prefix_policies", "secret_requests",
    "aws-secrets-manager", "aws-kms", "server",
]
```

Dependency graph:

```
server ──▶ myhandlers ──▶ myerrors
   │           │
   ├──▶ users
   ├──▶ groups
   ├──▶ prefix_policies
   ├──▶ secret_requests
   ├──▶ aws-kms
   └──▶ aws-secrets-manager
```

Domain crates depend only on `anyhow` + `sqlx` + `uuid` + `chrono`
(+ `serde_json` for `prefix_policies` tags).

---

## 4. Schema (7 tables)

Two-level approval. Group membership and approval policy both live in
the DB, editable by the admin UI (§5). The admin set itself is **not**
stored here — it lives in config (§5.4).

### `0_extensions.sql`
```sql
create extension if not exists "uuid-ossp";
```

### `1_users.sql`
```sql
create table if not exists users (
    user_id    uuid primary key default uuid_generate_v4(),
    user_email varchar(255) not null unique,
    created_at timestamptz not null default now()
);
```

### `2_secret_requests.sql`
Postgres enum `secret_request_status` with values
`PENDING_L1 | PENDING_L2 | APPROVED | REJECTED`, plus the table:
```sql
create table if not exists secret_requests (
    secret_request_id  uuid primary key default uuid_generate_v4(),
    secret_name        text not null,
    encrypted_value    text not null,
    requester_user_id  uuid not null references users(user_id),
    reason             text not null,
    status             secret_request_status not null default 'PENDING_L1',
    created_at         timestamptz not null default now(),
    resolved_at        timestamptz,

    check ((status in ('PENDING_L1', 'PENDING_L2')) = (resolved_at is null))
);
```

### `3_request_approvals.sql`
Postgres enums `approval_decision` (`APPROVED|REJECTED`) and
`approval_level` (`L1|L2`), plus:
```sql
create table if not exists request_approvals (
    approval_id        uuid primary key default uuid_generate_v4(),
    secret_request_id  uuid not null references secret_requests(secret_request_id),
    level              approval_level not null,
    decision           approval_decision not null,
    approver_user_id   uuid not null references users(user_id),
    approver_group     text not null,   -- group NAME at time of approval (snapshot)
    note               text,
    created_at         timestamptz not null default now(),
    unique (secret_request_id, level)
);
```
`approver_group` is a snapshot string, not a FK, so a renamed/deleted
group doesn't rewrite history.

### `4_groups.sql`
```sql
create table if not exists groups (
    group_id    uuid primary key default uuid_generate_v4(),
    group_name  text not null unique,
    description text,
    created_at  timestamptz not null default now()
);
```

### `5_user_group_memberships.sql`
```sql
create table if not exists user_group_memberships (
    user_id    uuid not null references users(user_id) on delete cascade,
    group_id   uuid not null references groups(group_id) on delete restrict,
    created_at timestamptz not null default now(),
    primary key (user_id, group_id)
);
```
- `on delete cascade` for `users`: deleting a user drops their memberships.
- `on delete restrict` for `groups`: a referenced group can't be deleted
  until it's empty and no `prefix_policies` row points at it.

### `6_prefix_policies.sql`
```sql
create table if not exists prefix_policies (
    policy_id            uuid primary key default uuid_generate_v4(),
    prefix               text not null unique,
    aws_account_id       text not null,
    aws_region           text not null,
    requester_group_id   uuid not null references groups(group_id) on delete restrict,
    l1_approver_group_id uuid not null references groups(group_id) on delete restrict,
    l2_approver_group_id uuid not null references groups(group_id) on delete restrict,
    tags                 text not null default '{}',   -- serialized JSON object of strings
    created_at           timestamptz not null default now(),
    updated_at           timestamptz not null default now()
);
```
- Unique on `prefix` — one policy per prefix string.
- `tags` is `text` (a serialized JSON object), not `jsonb`, to avoid
  pulling in sqlx's `json` feature; the crate parses on read and
  serializes on write.

### Cross-row invariants

Enforced inside `secret_requests::record_decision`'s transaction (cross-
row checks can't be `CHECK` constraints):

- **L1**: `approver_user_id <> secret_requests.requester_user_id` AND
  approver is a member of `prefix_policies.l1_approver_group_id`.
- **L2**: `approver_user_id ∉ {requester_user_id, L1.approver_user_id}` AND
  approver is a member of `prefix_policies.l2_approver_group_id`.
- Level can only be recorded when status matches (`PENDING_L1` → L1;
  `PENDING_L2` → L2).

### Audit trail

`request_approvals` is one row per decision (approver, group name, note,
timestamp). CloudTrail covers KMS + Secrets Manager calls. Admin actions
(group/policy edits) do not yet have a structured audit log — the
state-of-the-DB is the audit trail. A separate `admin_audit` table is a
deliberate v2.

### Sessions

No `oidc_sessions` / `pending_logins` tables. `tower-sessions` +
`PostgresStore` own theirs, auto-created at boot.

---

## 5. Policy — DB-driven, multi-account, admin-managed

Earlier revisions of this section put policy in `config.toml` as
`[[prefix]]` blocks. That's removed. Now:

- **Groups** are first-class rows in `groups`.
- **Users belong to groups** via `user_group_memberships` (many-to-many).
- **Prefix policies** are rows in `prefix_policies`. Each row binds a
  prefix string to an AWS account, an AWS region, three groups
  (requester / L1 / L2), and a tag map.
- **Cognito's group claim is ignored.** The portal looks up group
  membership in its own DB. Cognito provides only authenticated email.
- **Admins** = users whose email is in the config'd `admin_emails` list
  (§5.4). They edit groups, flows, and prefix policies through the web
  UI (§6). Admin set is **not** in the DB; cannot be elevated by a
  compromised app process.

### 5.1 Matching rule (unchanged from prior config-based model)

- `secret_name.starts_with(prefix)`.
- **Longest-prefix wins.** SQL: `where starts_with($1, prefix) order by length(prefix) desc limit 1`.
- DB-level uniqueness on `prefix` prevents two rows with the same prefix.
- End prefixes with `/` if you want a path boundary. For an exact match,
  store the full secret name as the prefix.

### 5.2 What the portal does per request

1. **Submit.** Look up the policy for the typed name (DB query). Miss →
   400. Requester ∉ `requester_group_id` → 403 (DB membership query).
2. **Approve L1.** Look up policy again. Approver ∉ `l1_approver_group_id`
   → 403. Approver = requester → 403. No AWS call.
3. **Approve L2.** Look up policy. Approver ∉ `l2_approver_group_id` →
   403. Approver ∈ {requester, L1 approver} → 403. KMS decrypt → read
   current value via `GetSecretValue` → merge patch → `PutSecretValue`
   with the merged JSON, applying the policy's `tags`.

### 5.3 Multi-account auth

Per-account credentials still live in `config.toml` — those are
deployment data, not user-managed. The format changes slightly: instead
of `[[aws_account]]` *plus* `[[prefix]]`, only `[[aws_account]]` remains:

```toml
[[aws_account]]
account_id = "111111111111"
role_arn   = "arn:aws:iam::111111111111:role/secrets-portal-writer"
```

At boot, the portal builds one `aws_sdk_secretsmanager::Client` per
declared account via `aws-config`'s `AssumeRoleProvider`. Same map on
`AppState` as before. If a `prefix_policies.aws_account_id` references
an account not declared in config, that policy's L2 approve fails at
runtime with a 500 — there's no way to mint credentials for it.

### 5.4 Admin set (config, not DB)

The set of admins is a list of email addresses in `config.toml`:

```toml
admin_emails = ["alice@company.com", "bob@company.com"]
```

`require_admin` checks the authenticated user's email (case-insensitive)
against this list. No DB lookup, no group membership, no UI to edit.

**Why config-only**:
- A compromised app cannot escalate privilege — the admin set is read
  at boot from a deployment artifact and never written to.
- No "cannot delete the admin group", "cannot remove last admin",
  or other guard-rail code; there's no admin-group-as-data to defend.
- Changes to the admin set are reviewed via the same PR flow as the
  rest of `config.toml`. Adding/removing an admin is a deploy.

**Tradeoff**: every admin change requires a redeploy. For a security
control with usually-stable membership, this is the right side of the
tradeoff. (Compare: gateway also keeps Cognito creds in config, not DB.)

### 5.5 Failure modes

| Scenario | Outcome |
|---|---|
| User types a name with no matching prefix | 400. |
| Prefix policy deleted between submit and approve | Approve returns 409; row stays pending until ops resolves it. |
| Group referenced by a prefix policy is deleted | Postgres rejects (`on delete restrict`). |
| User removed from `admin_emails` and redeployed | Next admin action returns 403. |
| AssumeRole fails at boot for one account | Boot fails. |
| AssumeRole creds expire at runtime | SDK auto-refreshes. |
| `PutSecretValue` returns `ResourceNotFoundException` | 500 "secret missing in AWS"; row stays pending; ops creates the secret in AWS or rejects the row. |

---

## 6. Routes (6)

| Method | Path                               | Purpose                                        |
|--------|------------------------------------|------------------------------------------------|
| GET    | `/`                                | Redirect to `/requests` or `/login`            |
| GET    | `/login` / `/callback` / `/logout` | Cognito hosted UI                              |
| GET    | `/requests`                        | My requests + L1 queue (if in any L1 group) + L2 queue (if in `l2_approver_group`) |
| GET    | `/requests/new`                    | Form (shows the L1 group the request will go to) |
| POST   | `/requests`                        | Create request                                 |
| GET    | `/requests/{id}`                   | Detail (no value shown; shows approval ladder) |
| POST   | `/requests/{id}/decision`          | Approve or reject at the current level         |

Route count unchanged. The decision handler derives the level from the
request's current status — the form has no `level` field, only `action`
(approve/reject) and `note`.

---

## 7. Session & auth

- `tower-sessions` with `PostgresStore`. `Expiry::OnInactivity(24h)`.
- `myhandlers::{login, callback, logout}` wrap gateway's shared
  `handlers` / `jwks` / `validation` crates. On `/callback` success:
  insert `"email"` and `"groups": Vec<String>` into the session, then
  `users::create_user(pool, &email)` (INSERT … ON CONFLICT DO NOTHING).
- `myhandlers::require_user(&session, &pool) -> Result<CurrentUser, AppError>`
  returns `{ user_id, email, groups }` or `AppError(401, …)`. Handlers
  translate 401 into a redirect to `/login`.
- `myhandlers::is_approver(groups: &[CognitoGroup], approver: &CognitoGroup) -> bool`.
- CSRF: `axum_csrf` + `server::csrf::{get_authenticity_token, verify_authenticity_token}`
  (one-shot token; copied from `gateway/server/src/csrf.rs`).

---

## 8. KMS + Secrets Manager

Two families of AWS calls: KMS encrypt/decrypt (portal's central key),
and Secrets Manager `PutSecretValue` (target account's secret). No
per-call timeout wrappers (§2.5); calls inherit SDK defaults.

### Secrets Manager — `aws-secrets-manager/` crate

Top-level workspace crate. One function + one newtype:

```rust
pub struct SecretName(pub String);

pub async fn put_secret_value(
    client: &Client, name: &SecretName, plaintext: &str,
) -> Result<()>;
```

The consumer picks which account's SDK client to pass (see §11).

### KMS — `server/src/aws.rs`

Single central KMS key in the portal's own account; one client on
`AppState`:

```rust
pub async fn encrypt_secret_value(kms: &kms::Client, key_arn: &str, plaintext: &str) -> Result<EncryptedValueB64>;
pub async fn decrypt_secret_value(kms: &kms::Client, ciphertext: &EncryptedValueB64) -> Result<String>;
```

Plaintext is a stack-local `String`, never persisted, never logged.
Secrets must already exist in target AWS accounts (pre-provisioned by
IaC); this app only calls `PutSecretValue`, never `CreateSecret`.

---

## 9. Handlers (`server/src/handlers/`)

One file per route. HTML inline via `format!`. `handlers::mod` exports
`esc(&str) -> String` (used for every interpolation of user text) and
`page(title: &str, body: &str) -> String` (the shell).

### Domain crate APIs

**`users`**
```rust
pub async fn create_user(pool: &PgPool, email: &str) -> Result<()>;
pub async fn get_user_id(pool: &PgPool, email: &str) -> Result<Uuid>;
```

No `user_managers` crate — there's no manager lookup. No `allowed_secrets`
crate — the requester types the secret name and the handler calls
`aws_secrets_manager::describe_secret` per submit/decision to check
existence and read tags. No cache, no dropdown (§5).

L1-queue eligibility still depends on knowing each PENDING_L1
request's `l1_approver_group`. Since there's no cache, the handler
calls `describe_secret` per pending row when rendering the queue.
That's `O(N)` API calls for `N` pending L1s — fine at the portal's
expected volume (dozens of requests/day). If it becomes a bottleneck,
add a short-TTL cache in `server/src/aws.rs` without changing any
contract.

**`secret_requests`**
```rust
pub struct Request {
    pub secret_request_id: SecretRequestId,
    pub secret_name: SecretName,
    pub encrypted_value: EncryptedValueB64,
    pub requester_user_id: Uuid,
    pub requester_email: String,            // joined from users
    pub reason: Reason,
    pub status: Status,                     // PendingL1 | PendingL2 | Approved | Rejected
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

pub struct Approval {
    pub approval_id: Uuid,
    pub level: ApprovalLevel,
    pub decision: Decision,
    pub approver_user_id: Uuid,
    pub approver_email: String,             // joined from users
    pub approver_group: CognitoGroup,       // snapshot of the group they matched as
    pub note: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub async fn create_request(
    pool: &PgPool,
    secret_name: &SecretName,
    encrypted_value: &EncryptedValueB64,
    requester_user_id: Uuid,
    reason: &Reason,
) -> Result<SecretRequestId>;

pub async fn get_request(pool: &PgPool, id: SecretRequestId) -> Result<Option<Request>>;
pub async fn list_approvals(pool: &PgPool, id: SecretRequestId) -> Result<Vec<Approval>>;

pub async fn list_my_requests(pool: &PgPool, requester_user_id: Uuid) -> Result<Vec<Request>>;

/// L1 queue — PENDING_L1 requests whose secret's `l1_approver_group`
/// is in the viewer's Cognito groups, and the viewer is not the requester.
/// The secret→group mapping comes from the cache, so this is a two-step
/// query: load all PENDING_L1 rows, then filter in Rust against the cache.
pub async fn list_pending_l1(pool: &PgPool) -> Result<Vec<Request>>;

/// L2 queue — PENDING_L2 rows where the viewer is not the requester and
/// not the L1 approver. Filter-by-user done in the handler after joining
/// on request_approvals for the L1 row.
pub async fn list_pending_l2(pool: &PgPool, viewer_user_id: Uuid) -> Result<Vec<Request>>;

/// Record an L1 decision atomically.
/// Transaction:
///   1. select secret_requests ... for update; assert status = 'PENDING_L1'
///   2. assert approver_user_id <> requester_user_id
///   3. insert request_approvals (level=1, decision, approver_group=..., ...)
///   4. update secret_requests set status =
///          case decision when APPROVED then 'PENDING_L2' else 'REJECTED' end,
///          resolved_at = case decision when REJECTED then now() else null end
///   5. commit
///
/// The caller (handler) has already verified approver ∈ secret's
/// `l1_approver_group` via the cache; `approver_group` is passed in for
/// the audit snapshot.
pub async fn record_l1_decision(
    pool: &PgPool,
    id: SecretRequestId,
    approver_user_id: Uuid,
    approver_group: &CognitoGroup,
    decision: Decision,
    note: Option<&str>,
) -> Result<Request>;

/// Record an L2 decision atomically.
/// Transaction:
///   1. select secret_requests ... for update; assert status = 'PENDING_L2'
///   2. select L1 row; assert approver_user_id ∉ {requester, L1.approver}
///   3. insert request_approvals (level=2, decision, approver_group=..., ...)
///   4. update secret_requests set status =
///          case decision when APPROVED then 'APPROVED' else 'REJECTED' end,
///          resolved_at = now()
///   5. commit
pub async fn record_l2_decision(
    pool: &PgPool,
    id: SecretRequestId,
    approver_user_id: Uuid,
    approver_group: &CognitoGroup,
    decision: Decision,
    note: Option<&str>,
) -> Result<Request>;
```

All names follow `verb_noun`. No tuple returns — `(Request, Vec<Approval>)`
for the detail page becomes two separate calls in the handler, because
§2.9 forbids bundled tuple returns.

### Submit handler (`new_request.rs`, POST)

```
1. require_user                                            -> {user_id, email, groups}
2. verify CSRF
3. policy = config.lookup_prefix(&form.secret_name)       // longest-match
       None                              ⇒ 400 "no matching prefix"
       policy.allowed_group ∉ groups     ⇒ 403 "not in allowed group"
4. encrypt_secret_value(&form.value)  →  EncryptedValueB64         [plaintext on stack]
5. create_request(...)                                             [plaintext dropped]
6. 303 → /requests/{id}
```

No dropdown — `/requests/new` is a plain text input for the secret
name. Names that don't match any configured prefix fail with 400.

### Decision handler (`decision.rs`, POST)

The handler derives the level from the request's current status — no
`level` field is trusted from the form. Eligibility at each level is
checked against the prefix policy looked up by `secret_name`:

```
1. require_user                                       -> {user_id, email, groups}
2. verify CSRF
3. request = secret_requests::get_request(id)
     None ⇒ 404
     status ∈ {Approved, Rejected} ⇒ 409

4. policy = config.lookup_prefix(&request.secret_name)
     None ⇒ 409 "no matching prefix" (config was changed after submit;
                                      row stays PENDING, ops resolves)

5. if request.status == PendingL1:
       if policy.l1_approver_group ∉ groups ⇒ 403 "not in L1 group"
       if user_id == requester_user_id      ⇒ 403 "self-approval"
       record_l1_decision(id, user_id, &policy.l1_approver_group, decision, note)

   else /* PendingL2 */:
       if config.l2_approver_group ∉ groups ⇒ 403 "not in L2 group"
       if user_id == requester_user_id      ⇒ 403 "self-approval"
       l1 = secret_requests::list_approvals(id).iter().find(level == L1)
       if user_id == l1.approver_user_id    ⇒ 403 "already approved at L1"
       if decision == APPROVED:
           sm        = app_state.sm_clients[&policy.aws_account_id];
           plaintext = decrypt_secret_value(&request.encrypted_value);
           put_secret_value(sm, &request.secret_name, &plaintext);
       record_l2_decision(id, user_id, &config.l2_approver_group, decision, note)

6. 303 → /requests/{id}
```

KMS decrypt + `PutSecretValue` happen **outside** the DB transaction to
avoid holding a row lock across network I/O. `record_l2_decision`
re-asserts `status = 'PENDING_L2'` inside its transaction; a racing
second L2 approver gets a 409 (and the first writer's value is the one
that stuck — safe because both decrypted the same ciphertext).

### Pages

- `/requests` — up to three `<table>`s, omitted when empty:
  1. **My requests** — `list_my_requests`.
  2. **Awaiting my L1 approval** — `list_pending_l1`, filtered
     in-handler by calling `describe_secret` on each row and keeping
     those whose `portal:l1-approver-group` tag is in the viewer's
     policy's `l1_approver_group` is in the viewer's groups and
     viewer ≠ requester. Pure config lookup per row — no API calls.
  3. **Awaiting my L2 approval** — `list_pending_l2` (only queried when
     the user is in `config.l2_approver_group`).
- `/requests/new` — plain text `<input>` for the secret name +
  `<input type="password" autocomplete="new-password">` for the value +
  `<textarea>` for reason + hidden CSRF. The form has no dropdown; a
  name that doesn't match any configured prefix fails on submit with 400.
- `/requests/{id}` — metadata table + an **approval ladder** rendered
  from `list_approvals(id)`:
  ```
  Submitted  2026-05-13 10:20  by alice@company.com
  L1         pending / approved / rejected by bob@company.com (payments-leads) at …
  L2         pending / approved / rejected by platform-user@… (security-team) at …
  ```
  Plus (when the viewer is eligible for the current level) two small
  forms POSTing to `/requests/{id}/decision` with `action=approve|reject`
  and a shared `note` field.

---

## 10. Config (`server/src/config.rs`)

```toml
host         = "127.0.0.1"
port         = 3000
database_url = "postgres://..."

kms_key_arn  = "arn:aws:kms:us-east-1:<portal-account>:key/…"   # central, portal's account

cognito_client_id     = "..."
cognito_client_secret = "..."
cognito_domain        = "..."
cognito_redirect_uri  = "http://localhost:3000/callback"
cognito_region        = "us-east-1"
cognito_user_pool_id  = "..."

csrf_cookie_key = "…64 comma-separated bytes…"
csrf_salt       = "…"

admin_emails = ["alice@company.com"]   # § 5.4 — admin set lives here, not DB

[[aws_account]]
account_id = "111111111111"
role_arn   = "arn:aws:iam::111111111111:role/secrets-portal-writer"
```

Scalar fields (host, port, database_url, kms_key_arn, cognito_*, csrf_*)
and `admin_emails` are **required** — no `#[serde(default)]` on any of
them. `aws_account` is a `Vec` — deserialized as empty if absent, but
validation at boot requires:

- ≥ 1 `[[aws_account]]` covering every `aws_account_id` that appears in
  the `prefix_policies` table at boot. (The rest of the policy lives in
  the DB and is editable through the admin UI; only the AWS credentials
  side stays in deployment-time config.)
- No two `[[aws_account]]` with the same `account_id`.

Boot fails with a clear error if any of these are violated.

`load_config()` composes `File::with_name("config")` +
`Environment::default()` and returns `anyhow::Result<AppConfig>`.

Environment file (`.env`) is loaded via `dotenv`, but its own result is
inspected — if `.env` parsing fails we log a static warning and continue,
we do not `.ok()` the result.

---

## 11. `AppState` (in `myhandlers/src/lib.rs`)

```rust
pub struct AppState {
    pub db_pool:     Arc<PgPool>,
    pub kms_client:  aws_sdk_kms::Client,              // portal's own account
    pub sm_clients:  HashMap<AccountId, aws_sdk_secretsmanager::Client>,
    pub kms_key_arn: String,
    pub l2_approver_group: CognitoGroup,
    pub prefix_policies:   Arc<Vec<PrefixPolicy>>,     // sorted longest-first

    // Cognito
    pub cognito_client_id: String,
    pub cognito_client_secret: String,
    pub cognito_domain: String,
    pub cognito_redirect_uri: String,
    pub cognito_region: String,
    pub cognito_user_pool_id: String,
}

pub struct PrefixPolicy {
    pub prefix:            String,
    pub aws_account_id:    AccountId,
    pub aws_region:        String,
    pub allowed_group:     CognitoGroup,
    pub l1_approver_group: CognitoGroup,
}

impl AppState {
    pub fn lookup_prefix(&self, secret_name: &str) -> Option<&PrefixPolicy> {
        self.prefix_policies.iter()
            .find(|p| secret_name.starts_with(&p.prefix))   // longest-first order
    }
    pub fn sm_client_for(&self, account: &AccountId) -> Option<&aws_sdk_secretsmanager::Client> {
        self.sm_clients.get(account)
    }
}
```

Lives in `myhandlers` (not `server`) because the Cognito shims that
consume these fields live there too, same split as gateway. `Clone`
derivation relies on every field being cheap to clone — SDK clients
are `Clone` by design, the pool and the policy list are behind `Arc`,
the `HashMap` of clients is small (bounded by account count).

---

## 12. Errors (`myerrors/src/lib.rs`)

```rust
pub struct AppError(pub StatusCode, pub String);

impl IntoResponse for AppError { ... }

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(err: E) -> Self {
        let _err = err.into();
        tracing::error!("internal error handling request");  // static message; no {err}
        Self(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".into())
    }
}
```

Key differences from `gateway/myerrors`:

- **Static log message.** No `{err}`, no `{err:#}`, no `{e}` in `error!`
  / `warn!` / `info!`. Per §2.2, the error is discarded into `_err`.
- No AWS-specific `From` variants (gateway maps Bedrock `ValidationException`
  to 400 by downcasting `SdkError`). If the user needs a specific
  non-500 status, the handler constructs `Err(AppError::new(status, msg))`
  explicitly.
- `AppError::new(status, msg)` is the only constructor that sets the
  user-visible message. Every other path goes through the blanket `From`
  and gets `"Internal server error"`.

Trade-off: we lose the server-side cause chain from logs in exchange for
no chance of leaking ciphertext / secret names / SDK payloads through
log aggregation. Post-mortems use CloudTrail (KMS and Secrets Manager
calls) plus the surrounding `tracing` span fields — fields we set
deliberately, not error interpolations.

---

## 13. `server/src/main.rs`

```
dotenv                                   (log a static warning if it errors)
tracing_subscriber::fmt::init()
load_config()                            // hard-fail on missing keys / bad prefix config
setup_database(&database_url)
sqlx::migrate!("../migrations").run(&pool)

aws_config::load_defaults(BehaviorVersion::latest())
build aws_sdk_kms::Client          (portal's own account)

for each [[aws_account]] in config:
    build an sdk_config with AssumeRoleProvider(role_arn)
    sm_clients.insert(account_id, aws_sdk_secretsmanager::Client::new(&sdk_config))
    // fail boot if AssumeRole fails for any account

sort config.prefixes by prefix length, descending    // longest-first lookup
build myhandlers::AppState { ... , sm_clients, prefix_policies: Arc::new(...) }

PostgresStore::new(pool).migrate()
spawn continuously_delete_expired(1h)    // AbortHandle
build CsrfLayer from the 64-byte key
SessionManagerLayer::new(store).with_expiry(OnInactivity(24h))
Router::new().route(...).layer(csrf).layer(session).with_state(state)
axum::serve(listener, app).with_graceful_shutdown(shutdown_signal(aborts))
```

`main() -> anyhow::Result<()>`. Everywhere uses `?`. No `unwrap`, no
`expect`. A bad config produces a non-zero exit with the full
`anyhow::Error` chain printed.

---

## 14. What was cut vs the first design

| Cut | Why |
|-----|-----|
| `allowed_secrets` table + crate | Replaced first by AWS tags, then by config prefixes (§5) |
| Tag-based discovery (`portal:managed`, `portal:allowed-group`, etc.) | Tags are editable by anyone with `TagResource`; config is deployment-owned |
| `aws_secrets_manager::describe_secret` + `SecretDescription` types | No longer needed — policy is pure config lookup |
| Portal-side cache (`PortalSecretsCache`, TTL refresh task) | Lookups are in-memory config hits; no AWS call needed on submit/L1 |
| Cognito `custom:manager_email` claim for L1 routing | Considered; blocked by ops. Then manager table. Now L1 = any member of the prefix's `l1_approver_group` — simplest |
| `user_managers` table + crate | Dropped: L1 is group-based, not person-based |
| `audit_log` table | `request_approvals` + CloudTrail already cover audit |
| `oidc_sessions`, `pending_logins` tables | `tower-sessions` owns them |
| Slack notifications | Not on the critical path |
| Separate `templates/` module, flash messages, a11y pass | Inline `format!` |
| `zeroize::Zeroizing` | Plaintext scope is one stack frame |
| `value_confirm` double-entry | Typo → reject & resubmit |
| Self-service cancel / `CANCELLED` status | Not in the goal |
| Separate approve/reject routes | One `/decision` with `action` field; level derived from status |
| Create-on-put for secrets | Pre-provisioned by IaC |
| Integration test harness + AWS mocks | Unit tests + manual smoke |
| Error-chain logging in `AppError` (gateway does this) | Static message only, per §2.2 |
| `thiserror`, typed domain error enums | Domain crates return `anyhow::Result<T>` |
| `_unbounded`/bounded wrappers on SDK calls | SDK has its own `TimeoutConfig` |

Kept (vs the single-crate cut earlier in this thread): top-level
workspace crates matching gateway.

---

## 15. Open decisions

1. Cross-account auth model = **AssumeRole** (portal's pod IAM → each
   account's `secrets-portal-writer` role). Confirm — or use cross-account
   resource policies on each secret with a single portal role.
2. Prefix-match boundary rule: require trailing `/`, or accept any
   `starts_with` match? Design currently accepts any `starts_with` with
   longest-wins; that's simpler but may surprise if someone writes a
   prefix without `/`.
3. SDK timeouts: accept defaults (`connect_timeout = 3.1s`, everything
   else unlimited) — OK for v1, or set `operation_timeout` now?
4. Commit `.sqlx/` cache (same as gateway)?
5. Reload config without restart (SIGHUP), or redeploy on every change?
   v1 default = redeploy.

Build order: migrations → `myerrors` → `users` → `secret_requests` →
`myhandlers` → `server/` (`config` including prefix validator, `database`,
`csrf`, `aws`, `handlers/*`, `main`).
