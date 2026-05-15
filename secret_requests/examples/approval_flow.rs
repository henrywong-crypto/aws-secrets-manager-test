use std::collections::HashMap;

use anyhow::{Context, Result};
use secret_requests::{Decision, create_request, get_request, list_approvals, record_decision};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

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

    let alice = upsert_user(&pool, "alice@example.com").await?;
    let bob   = upsert_user(&pool, "bob@example.com").await?;
    let carol = upsert_user(&pool, "carol@example.com").await?;
    let names: HashMap<Uuid, &str> =
        HashMap::from([(alice, "alice"), (bob, "bob"), (carol, "carol")]);

    println!("\n────── happy path ──────");
    let ok_id = create_request(
        &pool,
        "app/payments/prod/api-key",
        "ciphertext-placeholder",
        alice,
        "rotate per quarterly policy",
    )
    .await?;
    print_state(&pool, ok_id, &names, "after alice submits").await?;

    record_decision(&pool, ok_id, bob, "payments-leads", Decision::Approved, Some("LGTM")).await?;
    print_state(&pool, ok_id, &names, "after bob L1-approves").await?;

    record_decision(&pool, ok_id, carol, "security-team", Decision::Approved, Some("ok")).await?;
    print_state(&pool, ok_id, &names, "after carol L2-approves").await?;

    println!("\n────── rejection at L1 ──────");
    let rej_id = create_request(
        &pool,
        "app/payments/prod/api-key",
        "ciphertext-placeholder",
        alice,
        "suspicious value",
    )
    .await?;
    print_state(&pool, rej_id, &names, "after alice submits").await?;

    record_decision(
        &pool,
        rej_id,
        bob,
        "payments-leads",
        Decision::Rejected,
        Some("value looks wrong"),
    )
    .await?;
    print_state(&pool, rej_id, &names, "after bob L1-rejects").await?;

    println!("\n────── self-approval is blocked ──────");
    match record_decision(&pool, ok_id, alice, "payments-leads", Decision::Approved, None).await {
        Ok(()) => println!("  [unexpected] approve unexpectedly succeeded"),
        Err(err) => println!("  [expected error] {err}"),
    }

    Ok(())
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

async fn print_state(
    pool: &PgPool,
    id: Uuid,
    names: &HashMap<Uuid, &str>,
    label: &str,
) -> Result<()> {
    let req = get_request(pool, id).await?.context("request missing")?;
    let approvals = list_approvals(pool, id).await?;

    let requester = names.get(&req.requester_user_id).copied().unwrap_or("?");
    println!("\n{label}");
    println!("  id       {id}");
    println!("  name     {}", req.secret_name);
    println!("  by       {requester}");
    println!("  status   {:?}", req.status);
    if approvals.is_empty() {
        println!("  approvals   (none yet)");
    } else {
        for a in approvals {
            let who = names.get(&a.approver_user_id).copied().unwrap_or("?");
            let note = a.note.as_deref().unwrap_or("");
            println!(
                "  {:?}       {:?} by {who} ({}) — {note}",
                a.level, a.decision, a.approver_group
            );
        }
    }
    Ok(())
}
