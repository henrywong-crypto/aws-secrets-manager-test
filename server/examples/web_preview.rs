use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use approval_flows::Flow;
use axum::Router;
use axum::extract::{Form, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::get;
use myhandlers::AppError;
use prefix_policies::PrefixPolicy;
use secret_requests::{
    Approval, Decision, Request, Status, create_request, get_request, list_approvals,
    record_decision,
};
use serde::Deserialize;
use serde_json::{Map, Value};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio::sync::RwLock;
use uuid::Uuid;

const ADMIN_GROUP: &str = "portal-admins";

type SecretStore = Arc<RwLock<HashMap<String, Map<String, Value>>>>;

#[derive(Clone)]
struct AppCtx {
    pool: Arc<PgPool>,
    users: Arc<HashMap<String, Uuid>>,
    simulated_secrets: SecretStore,
}

#[derive(Deserialize)]
struct AsParam {
    #[serde(rename = "as", default = "default_as")]
    as_: String,
}

fn default_as() -> String {
    "alice@example.com".into()
}

#[derive(Deserialize)]
struct DecisionForm {
    action: String,
    note: String,
}

#[derive(Deserialize)]
struct NewGroupForm {
    group_name: String,
    description: String,
}

#[derive(Deserialize)]
struct AddMemberForm {
    user_email: String,
}

#[derive(Deserialize)]
struct UserIdForm {
    user_id: Uuid,
}

#[derive(Deserialize)]
struct PrefixForm {
    prefix: String,
    aws_account_id: String,
    aws_region: String,
    requester_group_id: Uuid,
    flow_id: Uuid,
    tags: String,
}

#[derive(Deserialize)]
struct FlowForm {
    flow_name: String,
    description: String,
    l1_approver_group_id: Uuid,
    l2_approver_group_id: Uuid,
}

#[tokio::main]
async fn main() -> Result<()> {
    let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL not set")?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .context("connect postgres")?;
    sqlx::migrate!("../migrations")
        .run(&pool)
        .await
        .context("run migrations")?;

    let users = seed(&pool).await?;
    let ctx = AppCtx {
        pool: Arc::new(pool),
        users: Arc::new(users),
        simulated_secrets: Arc::new(RwLock::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/", get(|| async { Redirect::to("/requests") }))
        .route("/requests", get(list_requests).post(submit_request))
        .route("/requests/new", get(new_request_form))
        .route("/requests/{id}", get(request_detail))
        .route(
            "/requests/{id}/action",
            get(action_form).post(submit_action),
        )
        .route("/admin", get(admin_index))
        .route(
            "/admin/groups",
            get(admin_groups_list).post(admin_groups_create),
        )
        .route("/admin/groups/{id}", get(admin_group_detail))
        .route(
            "/admin/groups/{id}/delete",
            axum::routing::post(admin_group_delete),
        )
        .route(
            "/admin/groups/{id}/members",
            axum::routing::post(admin_group_add_member),
        )
        .route(
            "/admin/groups/{id}/members/remove",
            axum::routing::post(admin_group_remove_member),
        )
        .route(
            "/admin/prefixes",
            get(admin_prefixes_list).post(admin_prefixes_create),
        )
        .route(
            "/admin/prefixes/{id}",
            get(admin_prefix_detail).post(admin_prefix_update),
        )
        .route(
            "/admin/prefixes/{id}/delete",
            axum::routing::post(admin_prefix_delete),
        )
        .route(
            "/admin/flows",
            get(admin_flows_list).post(admin_flows_create),
        )
        .route(
            "/admin/flows/{id}",
            get(admin_flow_detail).post(admin_flow_update),
        )
        .route(
            "/admin/flows/{id}/delete",
            axum::routing::post(admin_flow_delete),
        )
        .with_state(ctx);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("preview at http://127.0.0.1:3000");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn seed(pool: &PgPool) -> Result<HashMap<String, Uuid>> {
    let alice = upsert_user(pool, "alice@example.com").await?;
    let bob = upsert_user(pool, "bob@example.com").await?;
    let carol = upsert_user(pool, "carol@example.com").await?;
    let admin = upsert_user(pool, "admin@example.com").await?;

    let engineers = ensure_group(pool, "engineers", Some("default requesters")).await?;
    let engineering_leads = ensure_group(
        pool,
        "engineering-leads",
        Some("L1 approvers in default-flow"),
    )
    .await?;
    let platform_owners = ensure_group(
        pool,
        "platform-owners",
        Some("L2 approvers in default-flow"),
    )
    .await?;
    let pa = ensure_group(
        pool,
        ADMIN_GROUP,
        Some("May manage groups, flows, and prefix policies"),
    )
    .await?;

    groups::add_member(pool, alice, engineers).await?;
    groups::add_member(pool, bob, engineering_leads).await?;
    groups::add_member(pool, carol, platform_owners).await?;
    groups::add_member(pool, admin, pa).await?;

    if prefix_policies::list_policies(pool).await?.is_empty() {
        let flow_id = match approval_flows::get_flow_by_name(pool, "default-flow").await? {
            Some(f) => f.flow_id,
            None => {
                approval_flows::create_flow(
                    pool,
                    "default-flow",
                    Some("L1: engineering-leads. L2: platform-owners."),
                    engineering_leads,
                    platform_owners,
                )
                .await?
            }
        };
        let mut tags = HashMap::new();
        tags.insert("env".to_string(), "prod".to_string());
        prefix_policies::create_policy(
            pool,
            "app/payments/prod/",
            "111111111111",
            "us-east-1",
            engineers,
            flow_id,
            &tags,
        )
        .await?;
    }

    Ok(HashMap::from([
        ("alice@example.com".into(), alice),
        ("bob@example.com".into(), bob),
        ("carol@example.com".into(), carol),
        ("admin@example.com".into(), admin),
    ]))
}

async fn upsert_user(pool: &PgPool, email: &str) -> Result<Uuid> {
    sqlx::query_scalar(
        "insert into users (user_email) values ($1)
         on conflict (user_email) do update set user_email = excluded.user_email
         returning user_id",
    )
    .bind(email)
    .fetch_one(pool)
    .await
    .context("upsert user")
}

async fn ensure_group(pool: &PgPool, name: &str, description: Option<&str>) -> Result<Uuid> {
    if let Some(g) = groups::get_group_by_name(pool, name).await? {
        return Ok(g.group_id);
    }
    groups::create_group(pool, name, description).await
}

async fn list_requests(
    State(ctx): State<AppCtx>,
    Query(q): Query<AsParam>,
) -> Result<Html<String>, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;
    let viewer_groups = groups::list_groups_for_user(&ctx.pool, viewer_id).await?;
    let viewer_group_ids: Vec<Uuid> = viewer_groups.iter().map(|g| g.group_id).collect();
    let policies = prefix_policies::list_policies(&ctx.pool).await?;
    let flows = approval_flows::list_flows(&ctx.pool).await?;
    let flow_for = |flow_id: Uuid| flows.iter().find(|f| f.flow_id == flow_id);
    let l1_policies: Vec<&PrefixPolicy> = policies
        .iter()
        .filter(|p| {
            flow_for(p.flow_id).is_some_and(|f| viewer_group_ids.contains(&f.l1_approver_group_id))
        })
        .collect();
    let l2_policies: Vec<&PrefixPolicy> = policies
        .iter()
        .filter(|p| {
            flow_for(p.flow_id).is_some_and(|f| viewer_group_ids.contains(&f.l2_approver_group_id))
        })
        .collect();

    let all = fetch_all_requests(&ctx.pool).await?;
    let mine: Vec<&Request> = all
        .iter()
        .filter(|r| r.requester_user_id == viewer_id)
        .collect();
    let pending_l1: Vec<&Request> = all
        .iter()
        .filter(|r| {
            r.status == Status::PendingL1
                && r.requester_user_id != viewer_id
                && l1_policies
                    .iter()
                    .any(|p| r.secret_name.starts_with(&p.prefix))
        })
        .collect();
    let pending_l2: Vec<&Request> = all
        .iter()
        .filter(|r| {
            r.status == Status::PendingL2
                && r.requester_user_id != viewer_id
                && l2_policies
                    .iter()
                    .any(|p| r.secret_name.starts_with(&p.prefix))
        })
        .collect();

    let mut body = String::new();
    body.push_str(&format!(
        "<h1>Requests — acting as <b>{}</b></h1>",
        esc(&q.as_)
    ));

    body.push_str("<h2>My requests</h2>");
    body.push_str(&render_requests_table(&mine, &ctx, &q.as_, false));

    if !l1_policies.is_empty() {
        body.push_str("<h2>Awaiting my L1 approval</h2>");
        body.push_str(&render_requests_table(&pending_l1, &ctx, &q.as_, true));
    }
    if !l2_policies.is_empty() {
        body.push_str("<h2>Awaiting my L2 approval</h2>");
        body.push_str(&render_requests_table(&pending_l2, &ctx, &q.as_, true));
    }

    Ok(Html(page("Requests", &q.as_, "/requests", &body)))
}

async fn new_request_form(Query(q): Query<AsParam>) -> Html<String> {
    Html(page(
        "New request",
        &q.as_,
        "/requests/new",
        &render_new_request_form("", "", &[], 3, &q.as_),
    ))
}

async fn submit_request(
    State(ctx): State<AppCtx>,
    Query(q): Query<AsParam>,
    Form(form): Form<HashMap<String, String>>,
) -> Result<axum::response::Response, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;

    let action = form.get("action").map(String::as_str).unwrap_or("submit");
    let secret_name = form.get("secret_name").cloned().unwrap_or_default();
    let reason = form.get("reason").cloned().unwrap_or_default();

    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut max_idx: i64 = -1;
    for i in 0..1000 {
        let Some(k) = form.get(&format!("key_{i}")) else {
            break;
        };
        let v = form.get(&format!("value_{i}")).cloned().unwrap_or_default();
        pairs.push((k.clone(), v));
        max_idx = i as i64;
    }

    if action == "add_row" {
        let row_count = ((max_idx + 2).max(3)) as usize;
        let body = render_new_request_form(&secret_name, &reason, &pairs, row_count, &q.as_);
        return Ok(Html(page("New request", &q.as_, "/requests/new", &body)).into_response());
    }

    let filtered: Vec<(String, String)> = pairs
        .into_iter()
        .filter_map(|(k, v)| {
            let k = k.trim().to_string();
            if k.is_empty() { None } else { Some((k, v)) }
        })
        .collect();
    if filtered.is_empty() {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "patch must have at least one key",
        ));
    }

    let secret_name = secret_name.trim();
    let policy = prefix_policies::lookup_for_secret_name(&ctx.pool, secret_name)
        .await?
        .ok_or_else(|| AppError::new(StatusCode::BAD_REQUEST, "no matching prefix policy"))?;
    if !groups::is_member(&ctx.pool, viewer_id, policy.requester_group_id).await? {
        return Err(AppError::new(
            StatusCode::FORBIDDEN,
            "not in requester group",
        ));
    }

    let canonical: Map<String, Value> = filtered
        .into_iter()
        .map(|(k, v)| (k, Value::String(v)))
        .collect();
    let stored = serde_json::to_string(&canonical).context("serialize patch")?;

    let id = create_request(&ctx.pool, secret_name, &stored, viewer_id, reason.trim()).await?;
    Ok(Redirect::to(&format!("/requests/{id}?as={}", q.as_)).into_response())
}

fn render_new_request_form(
    secret_name: &str,
    reason: &str,
    pairs: &[(String, String)],
    rows: usize,
    viewer: &str,
) -> String {
    let mut rows_html = String::new();
    for i in 0..rows {
        let k = pairs.get(i).map(|(k, _)| k.as_str()).unwrap_or("");
        let v = pairs.get(i).map(|(_, v)| v.as_str()).unwrap_or("");
        rows_html.push_str(&format!(
            r#"<tr><td><input name="key_{i}" value="{k}"></td>
                <td><input name="value_{i}" type="password" value="{v}"></td></tr>"#,
            k = esc(k),
            v = esc(v),
        ));
    }
    format!(
        r#"<form method="post" action="/requests?as={viewer}">
          <h1>New request</h1>
          <fieldset>
            <legend>Request</legend>
            <p><label>Secret name<br><input name="secret_name" value="{name}" required></label></p>
            <p><label>Reason<br><textarea name="reason" rows="3" required>{reason}</textarea></label></p>
          </fieldset>
          <fieldset>
            <legend>Patch</legend>
            <p>One row per key. Empty rows are skipped on submit. On L2 approve the patch merges into the existing secret; new keys override.</p>
            <table>
              <tr><th>Key</th><th>Value</th></tr>
              {rows_html}
            </table>
            <p><button name="action" value="add_row">+ Add row</button></p>
          </fieldset>
          <p><button name="action" value="submit">Submit request</button></p>
        </form>"#,
        viewer = esc(viewer),
        name = esc(secret_name),
        reason = esc(reason),
        rows_html = rows_html,
    )
}

async fn request_detail(
    State(ctx): State<AppCtx>,
    Path(id): Path<Uuid>,
    Query(q): Query<AsParam>,
) -> Result<Html<String>, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;

    let req = get_request(&ctx.pool, id)
        .await?
        .ok_or_else(|| AppError::new(StatusCode::NOT_FOUND, "request not found"))?;
    let approvals = list_approvals(&ctx.pool, id).await?;
    let requester = email_for(&ctx, req.requester_user_id);
    let eligibility = eligibility(&ctx, &req, viewer_id).await?;

    let mut body = String::new();
    body.push_str(&format!(
        "<h1>Request <small>{id}</small></h1>\
         <table>\
         <tr><th>Secret</th><td>{}</td></tr>\
         <tr><th>Requester</th><td>{}</td></tr>\
         <tr><th>Reason</th><td>{}</td></tr>\
         <tr><th>Status</th><td>{:?}</td></tr>\
         <tr><th>Created</th><td>{}</td></tr>\
         <tr><th>Resolved</th><td>{}</td></tr>\
         </table>",
        esc(&req.secret_name),
        esc(&requester),
        esc(&req.reason),
        req.status,
        req.created_at,
        req.resolved_at
            .map(|t| t.to_string())
            .unwrap_or_else(|| "—".into()),
    ));

    body.push_str("<h2>Patch</h2>");
    body.push_str(&render_patch(&req.encrypted_value));

    body.push_str("<h2>Current value</h2>");
    let state = ctx.simulated_secrets.read().await;
    body.push_str(&render_secret_state(state.get(&req.secret_name)));
    drop(state);

    body.push_str("<h2>Approvals</h2>");
    body.push_str(&render_ladder(&approvals, &ctx));

    if eligibility.is_some() {
        body.push_str(&format!(
            "<p><a href=\"/requests/{id}/action?as={viewer}\">→ Act on this request</a></p>",
            viewer = esc(&q.as_),
        ));
    }

    Ok(Html(page(
        "Request",
        &q.as_,
        &format!("/requests/{id}"),
        &body,
    )))
}

async fn action_form(
    State(ctx): State<AppCtx>,
    Path(id): Path<Uuid>,
    Query(q): Query<AsParam>,
) -> Result<Html<String>, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;

    let req = get_request(&ctx.pool, id)
        .await?
        .ok_or_else(|| AppError::new(StatusCode::NOT_FOUND, "request not found"))?;
    let group = eligibility(&ctx, &req, viewer_id)
        .await?
        .ok_or_else(|| AppError::new(StatusCode::FORBIDDEN, "not eligible to act"))?;

    let body = format!(
        r#"<h1>Approve or reject</h1>
        <table>
          <tr><th>Secret</th><td>{secret}</td></tr>
          <tr><th>Requester</th><td>{requester}</td></tr>
          <tr><th>Status</th><td>{status:?}</td></tr>
          <tr><th>Acting as</th><td>{viewer}</td></tr>
          <tr><th>Via group</th><td>{group}</td></tr>
        </table>
        <h2>Patch</h2>
        {patch}
        <form method="post" action="/requests/{id}/action?as={viewer}">
          <fieldset>
            <legend>Decision</legend>
            <p><label>Note (optional)<br><textarea name="note" rows="3"></textarea></label></p>
            <p>
              <button name="action" value="approve">Approve</button>
              <button name="action" value="reject">Reject</button>
            </p>
          </fieldset>
        </form>
        <p><a href="/requests/{id}?as={viewer}">← Back</a></p>"#,
        secret = esc(&req.secret_name),
        requester = esc(&email_for(&ctx, req.requester_user_id)),
        status = req.status,
        viewer = esc(&q.as_),
        group = esc(&group),
        patch = render_patch(&req.encrypted_value),
    );
    Ok(Html(page(
        "Act",
        &q.as_,
        &format!("/requests/{id}/action"),
        &body,
    )))
}

async fn submit_action(
    State(ctx): State<AppCtx>,
    Path(id): Path<Uuid>,
    Query(q): Query<AsParam>,
    Form(form): Form<DecisionForm>,
) -> Result<Redirect, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;

    let req = get_request(&ctx.pool, id)
        .await?
        .ok_or_else(|| AppError::new(StatusCode::NOT_FOUND, "request not found"))?;
    let group = eligibility(&ctx, &req, viewer_id)
        .await?
        .ok_or_else(|| AppError::new(StatusCode::FORBIDDEN, "not eligible to act"))?;

    let decision = match form.action.as_str() {
        "approve" => Decision::Approved,
        "reject" => Decision::Rejected,
        _ => return Err(AppError::new(StatusCode::BAD_REQUEST, "unknown action")),
    };
    let note = Some(form.note.trim()).filter(|s| !s.is_empty());
    let was_pending_l2 = req.status == Status::PendingL2;

    record_decision(&ctx.pool, id, viewer_id, &group, decision, note).await?;

    if decision == Decision::Approved && was_pending_l2 {
        apply_patch(&ctx, &req.secret_name, &req.encrypted_value).await?;
    }

    Ok(Redirect::to(&format!("/requests/{id}?as={}", q.as_)))
}

async fn apply_patch(ctx: &AppCtx, secret_name: &str, patch_json: &str) -> Result<(), AppError> {
    let pairs = parse_patch(patch_json)?;
    let mut state = ctx.simulated_secrets.write().await;
    let entry = state.entry(secret_name.to_string()).or_default();
    for (k, v) in pairs {
        entry.insert(k, Value::String(v));
    }
    Ok(())
}

async fn eligibility(
    ctx: &AppCtx,
    req: &Request,
    viewer_id: Uuid,
) -> Result<Option<String>, AppError> {
    if viewer_id == req.requester_user_id {
        return Ok(None);
    }
    let policy = match prefix_policies::lookup_for_secret_name(&ctx.pool, &req.secret_name).await? {
        Some(p) => p,
        None => return Ok(None),
    };
    let flow = approval_flows::get_flow(&ctx.pool, policy.flow_id)
        .await?
        .ok_or_else(|| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "flow missing"))?;
    let group_id = match req.status {
        Status::PendingL1 => flow.l1_approver_group_id,
        Status::PendingL2 => flow.l2_approver_group_id,
        Status::Approved | Status::Rejected => return Ok(None),
    };
    if !groups::is_member(&ctx.pool, viewer_id, group_id).await? {
        return Ok(None);
    }
    let group = groups::get_group(&ctx.pool, group_id)
        .await?
        .ok_or_else(|| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "group missing"))?;
    Ok(Some(group.group_name))
}

async fn require_admin(ctx: &AppCtx, viewer_id: Uuid) -> Result<(), AppError> {
    let admin_group = groups::get_group_by_name(&ctx.pool, ADMIN_GROUP)
        .await?
        .ok_or_else(|| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "admin group missing"))?;
    if !groups::is_member(&ctx.pool, viewer_id, admin_group.group_id).await? {
        return Err(AppError::new(
            StatusCode::FORBIDDEN,
            "admin access required",
        ));
    }
    Ok(())
}

async fn admin_index(
    State(ctx): State<AppCtx>,
    Query(q): Query<AsParam>,
) -> Result<Html<String>, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;
    require_admin(&ctx, viewer_id).await?;

    let group_count = groups::list_groups(&ctx.pool).await?.len();
    let flow_count = approval_flows::list_flows(&ctx.pool).await?.len();
    let policy_count = prefix_policies::list_policies(&ctx.pool).await?.len();

    let body = format!(
        r#"<h1>Admin</h1>
        <ul>
          <li><a href="/admin/groups?as={as_}">Groups</a> ({group_count})</li>
          <li><a href="/admin/flows?as={as_}">Approval flows</a> ({flow_count})</li>
          <li><a href="/admin/prefixes?as={as_}">Prefix policies</a> ({policy_count})</li>
        </ul>"#,
        as_ = esc(&q.as_),
    );
    Ok(Html(page("Admin", &q.as_, "/admin", &body)))
}

async fn admin_groups_list(
    State(ctx): State<AppCtx>,
    Query(q): Query<AsParam>,
) -> Result<Html<String>, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;
    require_admin(&ctx, viewer_id).await?;

    let mut body = String::from(
        "<h1>Groups</h1><table><tr><th>Name</th><th>Description</th><th>Members</th><th></th></tr>",
    );
    for g in groups::list_groups(&ctx.pool).await? {
        let count = groups::list_members(&ctx.pool, g.group_id).await?.len();
        body.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td><a href=\"/admin/groups/{}?as={}\">edit</a></td></tr>",
            esc(&g.group_name),
            esc(g.description.as_deref().unwrap_or("")),
            count,
            g.group_id,
            esc(&q.as_),
        ));
    }
    body.push_str("</table>");

    body.push_str(&format!(
        r#"<h2>Create group</h2>
        <form method="post" action="/admin/groups?as={as_}">
          <p><label>Name<br><input name="group_name" required></label></p>
          <p><label>Description<br><input name="description"></label></p>
          <p><button type="submit">Create</button></p>
        </form>"#,
        as_ = esc(&q.as_),
    ));

    Ok(Html(page("Groups", &q.as_, "/admin/groups", &body)))
}

async fn admin_groups_create(
    State(ctx): State<AppCtx>,
    Query(q): Query<AsParam>,
    Form(form): Form<NewGroupForm>,
) -> Result<Redirect, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;
    require_admin(&ctx, viewer_id).await?;

    let name = form.group_name.trim();
    if name.is_empty() {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "group name required",
        ));
    }
    let description = Some(form.description.trim()).filter(|s| !s.is_empty());
    groups::create_group(&ctx.pool, name, description).await?;
    Ok(Redirect::to(&format!("/admin/groups?as={}", q.as_)))
}

async fn admin_group_detail(
    State(ctx): State<AppCtx>,
    Path(id): Path<Uuid>,
    Query(q): Query<AsParam>,
) -> Result<Html<String>, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;
    require_admin(&ctx, viewer_id).await?;

    let group = groups::get_group(&ctx.pool, id)
        .await?
        .ok_or_else(|| AppError::new(StatusCode::NOT_FOUND, "group not found"))?;
    let member_ids = groups::list_members(&ctx.pool, id).await?;

    let mut body = String::new();
    body.push_str(&format!(
        "<h1>Group: {}</h1><p>{}</p>",
        esc(&group.group_name),
        esc(group.description.as_deref().unwrap_or("")),
    ));

    body.push_str("<h2>Members</h2>");
    if member_ids.is_empty() {
        body.push_str("<p><i>none</i></p>");
    } else {
        body.push_str("<table><tr><th>Email</th><th></th></tr>");
        for uid in &member_ids {
            let email = email_for(&ctx, *uid);
            body.push_str(&format!(
                r#"<tr><td>{}</td><td>
                   <form method="post" action="/admin/groups/{id}/members/remove?as={as_}">
                     <input type="hidden" name="user_id" value="{uid}">
                     <button type="submit">remove</button>
                   </form></td></tr>"#,
                esc(&email),
                as_ = esc(&q.as_),
            ));
        }
        body.push_str("</table>");
    }

    body.push_str(&format!(
        r#"<h3>Add member</h3>
        <form method="post" action="/admin/groups/{id}/members?as={as_}">
          <p><label>User email (creates the user if not present)<br>
               <input name="user_email" required></label></p>
          <p><button type="submit">Add</button></p>
        </form>"#,
        as_ = esc(&q.as_),
    ));

    if group.group_name != ADMIN_GROUP {
        body.push_str(&format!(
            r#"<h3>Danger</h3>
            <form method="post" action="/admin/groups/{id}/delete?as={as_}">
              <button type="submit">Delete group</button>
              <span> (fails if any prefix policy still references it)</span>
            </form>"#,
            as_ = esc(&q.as_),
        ));
    }

    Ok(Html(page(
        "Group",
        &q.as_,
        &format!("/admin/groups/{id}"),
        &body,
    )))
}

async fn admin_group_delete(
    State(ctx): State<AppCtx>,
    Path(id): Path<Uuid>,
    Query(q): Query<AsParam>,
) -> Result<Redirect, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;
    require_admin(&ctx, viewer_id).await?;

    let group = groups::get_group(&ctx.pool, id)
        .await?
        .ok_or_else(|| AppError::new(StatusCode::NOT_FOUND, "group not found"))?;
    if group.group_name == ADMIN_GROUP {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "cannot delete portal-admins",
        ));
    }
    groups::delete_group(&ctx.pool, id).await?;
    Ok(Redirect::to(&format!("/admin/groups?as={}", q.as_)))
}

async fn admin_group_add_member(
    State(ctx): State<AppCtx>,
    Path(id): Path<Uuid>,
    Query(q): Query<AsParam>,
    Form(form): Form<AddMemberForm>,
) -> Result<Redirect, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;
    require_admin(&ctx, viewer_id).await?;

    let email = form.user_email.trim().to_lowercase();
    if email.is_empty() {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "email required"));
    }
    let user_id = upsert_user(&ctx.pool, &email).await?;
    groups::add_member(&ctx.pool, user_id, id).await?;
    Ok(Redirect::to(&format!("/admin/groups/{id}?as={}", q.as_)))
}

async fn admin_group_remove_member(
    State(ctx): State<AppCtx>,
    Path(id): Path<Uuid>,
    Query(q): Query<AsParam>,
    Form(form): Form<UserIdForm>,
) -> Result<Redirect, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;
    require_admin(&ctx, viewer_id).await?;

    if let Some(g) = groups::get_group(&ctx.pool, id).await?
        && g.group_name == ADMIN_GROUP
    {
        let admins = groups::list_members(&ctx.pool, id).await?;
        if admins.len() <= 1 {
            return Err(AppError::new(
                StatusCode::BAD_REQUEST,
                "cannot remove the last portal-admin",
            ));
        }
    }
    groups::remove_member(&ctx.pool, form.user_id, id).await?;
    Ok(Redirect::to(&format!("/admin/groups/{id}?as={}", q.as_)))
}

async fn admin_prefixes_list(
    State(ctx): State<AppCtx>,
    Query(q): Query<AsParam>,
) -> Result<Html<String>, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;
    require_admin(&ctx, viewer_id).await?;

    let policies = prefix_policies::list_policies(&ctx.pool).await?;
    let groups_list = groups::list_groups(&ctx.pool).await?;
    let flows_list = approval_flows::list_flows(&ctx.pool).await?;

    let mut body = String::from("<h1>Prefix policies</h1>");
    if policies.is_empty() {
        body.push_str("<p><i>none</i></p>");
    } else {
        body.push_str("<table><tr><th>Prefix</th><th>Account</th><th>Region</th><th>Requester</th><th>Flow</th><th>Tags</th><th></th></tr>");
        for p in &policies {
            body.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
                 <td><a href=\"/admin/prefixes/{}?as={}\">edit</a></td></tr>",
                esc(&p.prefix),
                esc(&p.aws_account_id),
                esc(&p.aws_region),
                esc(&group_name(&groups_list, p.requester_group_id)),
                esc(&flow_name(&flows_list, p.flow_id)),
                esc(&format_tags_inline(&p.tags)),
                p.policy_id,
                esc(&q.as_),
            ));
        }
        body.push_str("</table>");
    }

    if flows_list.is_empty() {
        body.push_str("<p><i>Create at least one approval flow before adding prefix policies — <a href=\"/admin/flows?as=");
        body.push_str(&esc(&q.as_));
        body.push_str("\">go to flows</a>.</i></p>");
    } else {
        body.push_str("<h2>Create prefix policy</h2>");
        body.push_str(&render_prefix_form(
            &format!("/admin/prefixes?as={}", esc(&q.as_)),
            &groups_list,
            &flows_list,
            None,
            "{}",
        ));
    }

    Ok(Html(page(
        "Prefix policies",
        &q.as_,
        "/admin/prefixes",
        &body,
    )))
}

async fn admin_prefixes_create(
    State(ctx): State<AppCtx>,
    Query(q): Query<AsParam>,
    Form(form): Form<PrefixForm>,
) -> Result<Redirect, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;
    require_admin(&ctx, viewer_id).await?;

    let tags = parse_tags(&form.tags)?;
    prefix_policies::create_policy(
        &ctx.pool,
        form.prefix.trim(),
        form.aws_account_id.trim(),
        form.aws_region.trim(),
        form.requester_group_id,
        form.flow_id,
        &tags,
    )
    .await?;
    Ok(Redirect::to(&format!("/admin/prefixes?as={}", q.as_)))
}

async fn admin_prefix_detail(
    State(ctx): State<AppCtx>,
    Path(id): Path<Uuid>,
    Query(q): Query<AsParam>,
) -> Result<Html<String>, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;
    require_admin(&ctx, viewer_id).await?;

    let policy = prefix_policies::get_policy(&ctx.pool, id)
        .await?
        .ok_or_else(|| AppError::new(StatusCode::NOT_FOUND, "policy not found"))?;
    let groups_list = groups::list_groups(&ctx.pool).await?;
    let flows_list = approval_flows::list_flows(&ctx.pool).await?;

    let tags_text = serde_json::to_string(&policy.tags).context("serialize tags")?;
    let mut body = format!("<h1>Prefix: {}</h1>", esc(&policy.prefix));
    body.push_str(&render_prefix_form(
        &format!("/admin/prefixes/{id}?as={}", esc(&q.as_)),
        &groups_list,
        &flows_list,
        Some(&policy),
        &tags_text,
    ));
    body.push_str(&format!(
        r#"<h2>Danger</h2>
        <form method="post" action="/admin/prefixes/{id}/delete?as={as_}">
          <button type="submit">Delete this prefix policy</button>
        </form>"#,
        as_ = esc(&q.as_),
    ));

    Ok(Html(page(
        "Prefix",
        &q.as_,
        &format!("/admin/prefixes/{id}"),
        &body,
    )))
}

async fn admin_prefix_update(
    State(ctx): State<AppCtx>,
    Path(id): Path<Uuid>,
    Query(q): Query<AsParam>,
    Form(form): Form<PrefixForm>,
) -> Result<Redirect, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;
    require_admin(&ctx, viewer_id).await?;

    let tags = parse_tags(&form.tags)?;
    prefix_policies::update_policy(
        &ctx.pool,
        id,
        form.prefix.trim(),
        form.aws_account_id.trim(),
        form.aws_region.trim(),
        form.requester_group_id,
        form.flow_id,
        &tags,
    )
    .await?;
    Ok(Redirect::to(&format!("/admin/prefixes/{id}?as={}", q.as_)))
}

async fn admin_prefix_delete(
    State(ctx): State<AppCtx>,
    Path(id): Path<Uuid>,
    Query(q): Query<AsParam>,
) -> Result<Redirect, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;
    require_admin(&ctx, viewer_id).await?;
    prefix_policies::delete_policy(&ctx.pool, id).await?;
    Ok(Redirect::to(&format!("/admin/prefixes?as={}", q.as_)))
}

fn resolve_viewer(ctx: &AppCtx, email: &str) -> Result<Uuid, AppError> {
    ctx.users
        .get(email)
        .copied()
        .ok_or_else(|| AppError::new(StatusCode::BAD_REQUEST, "unknown user"))
}

fn email_for(ctx: &AppCtx, user_id: Uuid) -> String {
    ctx.users
        .iter()
        .find(|(_, id)| **id == user_id)
        .map(|(e, _)| e.clone())
        .unwrap_or_else(|| user_id.to_string())
}

fn group_name(groups: &[groups::Group], id: Uuid) -> String {
    groups
        .iter()
        .find(|g| g.group_id == id)
        .map(|g| g.group_name.clone())
        .unwrap_or_else(|| id.to_string())
}

async fn fetch_all_requests(pool: &PgPool) -> Result<Vec<Request>, AppError> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "select secret_request_id from secret_requests order by created_at desc",
    )
    .fetch_all(pool)
    .await
    .context("list request ids")?;

    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(r) = get_request(pool, id).await? {
            out.push(r);
        }
    }
    Ok(out)
}

fn parse_patch(raw: &str) -> Result<Vec<(String, String)>, AppError> {
    let value: Value = serde_json::from_str(raw)
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "invalid JSON"))?;
    let obj = match value {
        Value::Object(m) => m,
        _ => {
            return Err(AppError::new(
                StatusCode::BAD_REQUEST,
                "JSON must be an object",
            ));
        }
    };
    if obj.is_empty() {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "patch must contain at least one key",
        ));
    }
    obj.into_iter()
        .map(|(k, v)| match v {
            Value::String(s) => Ok((k, s)),
            _ => Err(AppError::new(
                StatusCode::BAD_REQUEST,
                "all patch values must be strings",
            )),
        })
        .collect()
}

fn parse_tags(raw: &str) -> Result<HashMap<String, String>, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(HashMap::new());
    }
    let value: Value = serde_json::from_str(trimmed)
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "invalid JSON in tags"))?;
    let obj = match value {
        Value::Object(m) => m,
        _ => {
            return Err(AppError::new(
                StatusCode::BAD_REQUEST,
                "tags must be a JSON object",
            ));
        }
    };
    obj.into_iter()
        .map(|(k, v)| match v {
            Value::String(s) => Ok((k, s)),
            _ => Err(AppError::new(
                StatusCode::BAD_REQUEST,
                "all tag values must be strings",
            )),
        })
        .collect()
}

fn render_requests_table(
    rows: &[&Request],
    ctx: &AppCtx,
    viewer: &str,
    show_requester: bool,
) -> String {
    if rows.is_empty() {
        return "<p><i>none</i></p>".into();
    }
    let mut s = String::from("<table><tr><th>Secret</th>");
    if show_requester {
        s.push_str("<th>Requester</th>");
    }
    s.push_str("<th>Status</th><th>Created</th><th></th></tr>");
    for r in rows {
        s.push_str(&format!("<tr><td>{}</td>", esc(&r.secret_name)));
        if show_requester {
            s.push_str(&format!(
                "<td>{}</td>",
                esc(&email_for(ctx, r.requester_user_id))
            ));
        }
        s.push_str(&format!(
            "<td>{:?}</td><td>{}</td><td><a href=\"/requests/{}?as={}\">open</a></td></tr>",
            r.status,
            r.created_at,
            r.secret_request_id,
            esc(viewer),
        ));
    }
    s.push_str("</table>");
    s
}

fn render_patch(json_str: &str) -> String {
    match serde_json::from_str::<Value>(json_str) {
        Ok(Value::Object(obj)) if !obj.is_empty() => {
            let mut s = String::from("<table><tr><th>Key</th><th>New value</th></tr>");
            for (k, v) in obj {
                let display = v
                    .as_str()
                    .map(String::from)
                    .unwrap_or_else(|| v.to_string());
                s.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td></tr>",
                    esc(&k),
                    esc(&display)
                ));
            }
            s.push_str("</table>");
            s
        }
        _ => "<p><em>(could not parse patch)</em></p>".into(),
    }
}

fn render_secret_state(obj: Option<&Map<String, Value>>) -> String {
    let Some(obj) = obj else {
        return "<p><em>(no value stored yet — this secret would not exist in AWS)</em></p>".into();
    };
    if obj.is_empty() {
        return "<p><em>(empty)</em></p>".into();
    }
    let mut s = String::from("<table><tr><th>Key</th><th>Value</th></tr>");
    for (k, v) in obj {
        let display = v
            .as_str()
            .map(String::from)
            .unwrap_or_else(|| v.to_string());
        s.push_str(&format!(
            "<tr><td>{}</td><td>{}</td></tr>",
            esc(k),
            esc(&display)
        ));
    }
    s.push_str("</table>");
    s
}

fn render_ladder(approvals: &[Approval], ctx: &AppCtx) -> String {
    if approvals.is_empty() {
        return "<p><i>no approvals yet</i></p>".into();
    }
    let mut s = String::from(
        "<table><tr><th>Level</th><th>Decision</th><th>By</th><th>Group</th><th>Note</th><th>When</th></tr>",
    );
    for a in approvals {
        s.push_str(&format!(
            "<tr><td>{:?}</td><td>{:?}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            a.level,
            a.decision,
            esc(&email_for(ctx, a.approver_user_id)),
            esc(&a.approver_group),
            esc(a.note.as_deref().unwrap_or("")),
            a.created_at,
        ));
    }
    s.push_str("</table>");
    s
}

async fn admin_flows_list(
    State(ctx): State<AppCtx>,
    Query(q): Query<AsParam>,
) -> Result<Html<String>, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;
    require_admin(&ctx, viewer_id).await?;

    let flows = approval_flows::list_flows(&ctx.pool).await?;
    let groups_list = groups::list_groups(&ctx.pool).await?;

    let mut body = String::from("<h1>Approval flows</h1>");
    if flows.is_empty() {
        body.push_str("<p><i>none</i></p>");
    } else {
        body.push_str(
            "<table><tr><th>Name</th><th>Description</th><th>L1</th><th>L2</th><th></th></tr>",
        );
        for f in &flows {
            body.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
                 <td><a href=\"/admin/flows/{}?as={}\">edit</a></td></tr>",
                esc(&f.flow_name),
                esc(f.description.as_deref().unwrap_or("")),
                esc(&group_name(&groups_list, f.l1_approver_group_id)),
                esc(&group_name(&groups_list, f.l2_approver_group_id)),
                f.flow_id,
                esc(&q.as_),
            ));
        }
        body.push_str("</table>");
    }

    body.push_str("<h2>Create flow</h2>");
    body.push_str(&render_flow_form(
        &format!("/admin/flows?as={}", esc(&q.as_)),
        &groups_list,
        None,
    ));

    Ok(Html(page("Flows", &q.as_, "/admin/flows", &body)))
}

async fn admin_flows_create(
    State(ctx): State<AppCtx>,
    Query(q): Query<AsParam>,
    Form(form): Form<FlowForm>,
) -> Result<Redirect, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;
    require_admin(&ctx, viewer_id).await?;

    let name = form.flow_name.trim();
    if name.is_empty() {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "flow name required"));
    }
    if form.l1_approver_group_id == form.l2_approver_group_id {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "L1 and L2 must be different groups",
        ));
    }
    let description = Some(form.description.trim()).filter(|s| !s.is_empty());
    approval_flows::create_flow(
        &ctx.pool,
        name,
        description,
        form.l1_approver_group_id,
        form.l2_approver_group_id,
    )
    .await?;
    Ok(Redirect::to(&format!("/admin/flows?as={}", q.as_)))
}

async fn admin_flow_detail(
    State(ctx): State<AppCtx>,
    Path(id): Path<Uuid>,
    Query(q): Query<AsParam>,
) -> Result<Html<String>, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;
    require_admin(&ctx, viewer_id).await?;

    let flow = approval_flows::get_flow(&ctx.pool, id)
        .await?
        .ok_or_else(|| AppError::new(StatusCode::NOT_FOUND, "flow not found"))?;
    let groups_list = groups::list_groups(&ctx.pool).await?;

    let mut body = format!("<h1>Flow: {}</h1>", esc(&flow.flow_name));
    body.push_str(&render_flow_form(
        &format!("/admin/flows/{id}?as={}", esc(&q.as_)),
        &groups_list,
        Some(&flow),
    ));
    body.push_str(&format!(
        r#"<h2>Danger</h2>
        <form method="post" action="/admin/flows/{id}/delete?as={as_}">
          <button type="submit">Delete this flow</button>
          <span> (fails if any prefix policy still uses it)</span>
        </form>"#,
        as_ = esc(&q.as_),
    ));

    Ok(Html(page(
        "Flow",
        &q.as_,
        &format!("/admin/flows/{id}"),
        &body,
    )))
}

async fn admin_flow_update(
    State(ctx): State<AppCtx>,
    Path(id): Path<Uuid>,
    Query(q): Query<AsParam>,
    Form(form): Form<FlowForm>,
) -> Result<Redirect, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;
    require_admin(&ctx, viewer_id).await?;

    let name = form.flow_name.trim();
    if name.is_empty() {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "flow name required"));
    }
    if form.l1_approver_group_id == form.l2_approver_group_id {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "L1 and L2 must be different groups",
        ));
    }
    let description = Some(form.description.trim()).filter(|s| !s.is_empty());
    approval_flows::update_flow(
        &ctx.pool,
        id,
        name,
        description,
        form.l1_approver_group_id,
        form.l2_approver_group_id,
    )
    .await?;
    Ok(Redirect::to(&format!("/admin/flows/{id}?as={}", q.as_)))
}

async fn admin_flow_delete(
    State(ctx): State<AppCtx>,
    Path(id): Path<Uuid>,
    Query(q): Query<AsParam>,
) -> Result<Redirect, AppError> {
    let viewer_id = resolve_viewer(&ctx, &q.as_)?;
    require_admin(&ctx, viewer_id).await?;
    approval_flows::delete_flow(&ctx.pool, id).await?;
    Ok(Redirect::to(&format!("/admin/flows?as={}", q.as_)))
}

fn flow_name(flows: &[Flow], id: Uuid) -> String {
    flows
        .iter()
        .find(|f| f.flow_id == id)
        .map(|f| f.flow_name.clone())
        .unwrap_or_else(|| id.to_string())
}

fn format_tags_inline(tags: &HashMap<String, String>) -> String {
    if tags.is_empty() {
        "—".into()
    } else {
        let mut entries: Vec<String> = tags.iter().map(|(k, v)| format!("{k}={v}")).collect();
        entries.sort();
        entries.join(", ")
    }
}

fn render_flow_form(action: &str, all_groups: &[groups::Group], existing: Option<&Flow>) -> String {
    let name = existing.map(|f| f.flow_name.as_str()).unwrap_or("");
    let description = existing
        .and_then(|f| f.description.as_deref())
        .unwrap_or("");
    let l1 = existing.map(|f| f.l1_approver_group_id);
    let l2 = existing.map(|f| f.l2_approver_group_id);

    let opts = |selected: Option<Uuid>| -> String {
        let mut s = String::new();
        for g in all_groups {
            let sel = if selected == Some(g.group_id) {
                " selected"
            } else {
                ""
            };
            s.push_str(&format!(
                "<option value=\"{}\"{}>{}</option>",
                g.group_id,
                sel,
                esc(&g.group_name),
            ));
        }
        s
    };

    format!(
        r#"<form method="post" action="{action}">
        <p><label>Flow name<br><input name="flow_name" value="{name}" required></label></p>
        <p><label>Description<br><input name="description" value="{description}"></label></p>
        <p><label>L1 approver group<br><select name="l1_approver_group_id" required>{l1_opts}</select></label></p>
        <p><label>L2 approver group<br><select name="l2_approver_group_id" required>{l2_opts}</select></label></p>
        <p><button type="submit">Save</button></p>
        </form>"#,
        name = esc(name),
        description = esc(description),
        l1_opts = opts(l1),
        l2_opts = opts(l2),
    )
}

fn render_prefix_form(
    action: &str,
    all_groups: &[groups::Group],
    all_flows: &[Flow],
    existing: Option<&PrefixPolicy>,
    tags_text: &str,
) -> String {
    let prefix = existing.map(|p| p.prefix.as_str()).unwrap_or("");
    let account = existing.map(|p| p.aws_account_id.as_str()).unwrap_or("");
    let region = existing
        .map(|p| p.aws_region.as_str())
        .unwrap_or("us-east-1");
    let req_group = existing.map(|p| p.requester_group_id);
    let flow = existing.map(|p| p.flow_id);

    let group_opts = |selected: Option<Uuid>| -> String {
        let mut s = String::new();
        for g in all_groups {
            let sel = if selected == Some(g.group_id) {
                " selected"
            } else {
                ""
            };
            s.push_str(&format!(
                "<option value=\"{}\"{}>{}</option>",
                g.group_id,
                sel,
                esc(&g.group_name),
            ));
        }
        s
    };
    let flow_opts = |selected: Option<Uuid>| -> String {
        let mut s = String::new();
        for f in all_flows {
            let sel = if selected == Some(f.flow_id) {
                " selected"
            } else {
                ""
            };
            s.push_str(&format!(
                "<option value=\"{}\"{}>{}</option>",
                f.flow_id,
                sel,
                esc(&f.flow_name),
            ));
        }
        s
    };

    format!(
        r#"<form method="post" action="{action}">
        <p><label>Prefix<br><input name="prefix" value="{prefix}" required></label></p>
        <p><label>AWS account ID<br><input name="aws_account_id" value="{account}" required></label></p>
        <p><label>AWS region<br><input name="aws_region" value="{region}" required></label></p>
        <p><label>Requester group<br><select name="requester_group_id" required>{req_opts}</select></label></p>
        <p><label>Approval flow<br><select name="flow_id" required>{f_opts}</select></label></p>
        <p><label>Tags (JSON object of strings, applied on every PutSecretValue)<br>
             <textarea name="tags" rows="4">{tags}</textarea></label></p>
        <p><button type="submit">Save</button></p>
        </form>"#,
        prefix = esc(prefix),
        account = esc(account),
        region = esc(region),
        req_opts = group_opts(req_group),
        f_opts = flow_opts(flow),
        tags = esc(tags_text),
    )
}

fn page(title: &str, viewer: &str, here: &str, body: &str) -> String {
    let viewer_e = esc(viewer);
    let here_e = esc(here);
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{title}</title></head><body>
<header>
<nav>
  <a href="/requests?as={viewer_e}">Requests</a>
  <a href="/requests/new?as={viewer_e}">New request</a>
  <a href="/admin?as={viewer_e}">Admin</a>
</nav>
<p><small>acting as <b>{viewer_e}</b> · switch:
  <a href="{here_e}?as=alice@example.com">alice</a>
  <a href="{here_e}?as=bob@example.com">bob</a>
  <a href="{here_e}?as=carol@example.com">carol</a>
  <a href="{here_e}?as=admin@example.com">admin</a></small></p>
</header>
<main>
{body}
</main>
<footer><small>preview · no auth · no encryption</small></footer>
</body></html>"#
    )
}

fn esc(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '&' => "&amp;".into(),
            '"' => "&quot;".into(),
            '\'' => "&#39;".into(),
            c => c.to_string(),
        })
        .collect()
}
