use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Flow {
    pub flow_id: Uuid,
    pub flow_name: String,
    pub description: Option<String>,
    pub l1_approver_group_id: Uuid,
    pub l2_approver_group_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn create_flow(
    pool: &PgPool,
    name: &str,
    description: Option<&str>,
    l1_approver_group_id: Uuid,
    l2_approver_group_id: Uuid,
) -> Result<Uuid> {
    sqlx::query_scalar!(
        "insert into approval_flows (flow_name, description, l1_approver_group_id, l2_approver_group_id)
         values ($1, $2, $3, $4)
         returning flow_id",
        name,
        description,
        l1_approver_group_id,
        l2_approver_group_id,
    )
    .fetch_one(pool)
    .await
    .context("insert flow")
}

pub async fn update_flow(
    pool: &PgPool,
    id: Uuid,
    name: &str,
    description: Option<&str>,
    l1_approver_group_id: Uuid,
    l2_approver_group_id: Uuid,
) -> Result<()> {
    sqlx::query!(
        "update approval_flows
         set flow_name = $1, description = $2,
             l1_approver_group_id = $3, l2_approver_group_id = $4,
             updated_at = now()
         where flow_id = $5",
        name,
        description,
        l1_approver_group_id,
        l2_approver_group_id,
        id,
    )
    .execute(pool)
    .await
    .context("update flow")?;
    Ok(())
}

pub async fn delete_flow(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query!("delete from approval_flows where flow_id = $1", id)
        .execute(pool)
        .await
        .context("delete flow")?;
    Ok(())
}

pub async fn list_flows(pool: &PgPool) -> Result<Vec<Flow>> {
    sqlx::query_as!(
        Flow,
        "select flow_id, flow_name, description,
                l1_approver_group_id, l2_approver_group_id,
                created_at, updated_at
         from approval_flows
         order by flow_name",
    )
    .fetch_all(pool)
    .await
    .context("list flows")
}

pub async fn get_flow(pool: &PgPool, id: Uuid) -> Result<Option<Flow>> {
    sqlx::query_as!(
        Flow,
        "select flow_id, flow_name, description,
                l1_approver_group_id, l2_approver_group_id,
                created_at, updated_at
         from approval_flows
         where flow_id = $1",
        id,
    )
    .fetch_optional(pool)
    .await
    .context("get flow")
}

pub async fn get_flow_by_name(pool: &PgPool, name: &str) -> Result<Option<Flow>> {
    sqlx::query_as!(
        Flow,
        "select flow_id, flow_name, description,
                l1_approver_group_id, l2_approver_group_id,
                created_at, updated_at
         from approval_flows
         where flow_name = $1",
        name,
    )
    .fetch_optional(pool)
    .await
    .context("get flow by name")
}
