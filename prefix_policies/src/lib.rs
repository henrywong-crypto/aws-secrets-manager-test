use std::collections::HashMap;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct PrefixPolicy {
    pub policy_id: Uuid,
    pub prefix: String,
    pub aws_account_id: String,
    pub aws_region: String,
    pub requester_group_id: Uuid,
    pub flow_id: Uuid,
    pub tags: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[allow(clippy::too_many_arguments)]
pub async fn create_policy(
    pool: &PgPool,
    prefix: &str,
    aws_account_id: &str,
    aws_region: &str,
    requester_group_id: Uuid,
    flow_id: Uuid,
    tags: &HashMap<String, String>,
) -> Result<Uuid> {
    let tags_json = serde_json::to_string(tags).context("serialize tags")?;
    sqlx::query_scalar!(
        "insert into prefix_policies
           (prefix, aws_account_id, aws_region, requester_group_id, flow_id, tags)
         values ($1, $2, $3, $4, $5, $6)
         returning policy_id",
        prefix,
        aws_account_id,
        aws_region,
        requester_group_id,
        flow_id,
        tags_json,
    )
    .fetch_one(pool)
    .await
    .context("insert prefix_policy")
}

#[allow(clippy::too_many_arguments)]
pub async fn update_policy(
    pool: &PgPool,
    id: Uuid,
    prefix: &str,
    aws_account_id: &str,
    aws_region: &str,
    requester_group_id: Uuid,
    flow_id: Uuid,
    tags: &HashMap<String, String>,
) -> Result<()> {
    let tags_json = serde_json::to_string(tags).context("serialize tags")?;
    sqlx::query!(
        "update prefix_policies
         set prefix = $1, aws_account_id = $2, aws_region = $3,
             requester_group_id = $4, flow_id = $5,
             tags = $6, updated_at = now()
         where policy_id = $7",
        prefix,
        aws_account_id,
        aws_region,
        requester_group_id,
        flow_id,
        tags_json,
        id,
    )
    .execute(pool)
    .await
    .context("update prefix_policy")?;
    Ok(())
}

pub async fn delete_policy(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query!("delete from prefix_policies where policy_id = $1", id)
        .execute(pool)
        .await
        .context("delete prefix_policy")?;
    Ok(())
}

pub async fn list_policies(pool: &PgPool) -> Result<Vec<PrefixPolicy>> {
    let rows = sqlx::query!(
        "select policy_id, prefix, aws_account_id, aws_region,
                requester_group_id, flow_id, tags, created_at, updated_at
         from prefix_policies
         order by length(prefix) desc, prefix",
    )
    .fetch_all(pool)
    .await
    .context("list prefix_policies")?;

    rows.into_iter()
        .map(|r| {
            Ok(PrefixPolicy {
                policy_id: r.policy_id,
                prefix: r.prefix,
                aws_account_id: r.aws_account_id,
                aws_region: r.aws_region,
                requester_group_id: r.requester_group_id,
                flow_id: r.flow_id,
                tags: serde_json::from_str(&r.tags).context("parse tags")?,
                created_at: r.created_at,
                updated_at: r.updated_at,
            })
        })
        .collect()
}

pub async fn get_policy(pool: &PgPool, id: Uuid) -> Result<Option<PrefixPolicy>> {
    let row = sqlx::query!(
        "select policy_id, prefix, aws_account_id, aws_region,
                requester_group_id, flow_id, tags, created_at, updated_at
         from prefix_policies
         where policy_id = $1",
        id,
    )
    .fetch_optional(pool)
    .await
    .context("get prefix_policy")?;

    let Some(r) = row else { return Ok(None) };
    Ok(Some(PrefixPolicy {
        policy_id: r.policy_id,
        prefix: r.prefix,
        aws_account_id: r.aws_account_id,
        aws_region: r.aws_region,
        requester_group_id: r.requester_group_id,
        flow_id: r.flow_id,
        tags: serde_json::from_str(&r.tags).context("parse tags")?,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }))
}

pub async fn lookup_for_secret_name(
    pool: &PgPool,
    secret_name: &str,
) -> Result<Option<PrefixPolicy>> {
    let row = sqlx::query!(
        "select policy_id, prefix, aws_account_id, aws_region,
                requester_group_id, flow_id, tags, created_at, updated_at
         from prefix_policies
         where starts_with($1, prefix)
         order by length(prefix) desc
         limit 1",
        secret_name,
    )
    .fetch_optional(pool)
    .await
    .context("lookup prefix_policy")?;

    let Some(r) = row else { return Ok(None) };
    Ok(Some(PrefixPolicy {
        policy_id: r.policy_id,
        prefix: r.prefix,
        aws_account_id: r.aws_account_id,
        aws_region: r.aws_region,
        requester_group_id: r.requester_group_id,
        flow_id: r.flow_id,
        tags: serde_json::from_str(&r.tags).context("parse tags")?,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }))
}
