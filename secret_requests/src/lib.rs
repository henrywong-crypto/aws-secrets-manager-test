use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "secret_request_status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    PendingL1,
    PendingL2,
    Approved,
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "approval_decision", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Approved,
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "approval_level")]
pub enum ApprovalLevel {
    L1,
    L2,
}

#[derive(Clone, Debug)]
pub struct Request {
    pub secret_request_id: Uuid,
    pub secret_name:       String,
    pub encrypted_value:   String,
    pub requester_user_id: Uuid,
    pub reason:            String,
    pub status:            Status,
    pub created_at:        DateTime<Utc>,
    pub resolved_at:       Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct Approval {
    pub approval_id:      Uuid,
    pub level:            ApprovalLevel,
    pub decision:         Decision,
    pub approver_user_id: Uuid,
    pub approver_group:   String,
    pub note:             Option<String>,
    pub created_at:       DateTime<Utc>,
}

pub async fn create_request(
    pool: &PgPool,
    secret_name: &str,
    encrypted_value: &str,
    requester_user_id: Uuid,
    reason: &str,
) -> Result<Uuid> {
    sqlx::query_scalar!(
        "insert into secret_requests (secret_name, encrypted_value, requester_user_id, reason)
         values ($1, $2, $3, $4)
         returning secret_request_id",
        secret_name,
        encrypted_value,
        requester_user_id,
        reason,
    )
    .fetch_one(pool)
    .await
    .context("insert secret_request")
}

pub async fn get_request(pool: &PgPool, id: Uuid) -> Result<Option<Request>> {
    sqlx::query_as!(
        Request,
        r#"select secret_request_id,
                  secret_name,
                  encrypted_value,
                  requester_user_id,
                  reason,
                  status as "status: Status",
                  created_at,
                  resolved_at
           from secret_requests
           where secret_request_id = $1"#,
        id,
    )
    .fetch_optional(pool)
    .await
    .context("fetch request")
}

pub async fn list_approvals(pool: &PgPool, id: Uuid) -> Result<Vec<Approval>> {
    sqlx::query_as!(
        Approval,
        r#"select approval_id,
                  level    as "level: ApprovalLevel",
                  decision as "decision: Decision",
                  approver_user_id,
                  approver_group,
                  note,
                  created_at
           from request_approvals
           where secret_request_id = $1
           order by level"#,
        id,
    )
    .fetch_all(pool)
    .await
    .context("fetch approvals")
}

pub async fn record_decision(
    pool: &PgPool,
    id: Uuid,
    approver_user_id: Uuid,
    approver_group: &str,
    decision: Decision,
    note: Option<&str>,
) -> Result<()> {
    let mut tx = pool.begin().await.context("begin tx")?;

    let row = sqlx::query!(
        r#"select requester_user_id,
                  status as "status: Status"
           from secret_requests
           where secret_request_id = $1
           for update"#,
        id,
    )
    .fetch_optional(&mut *tx)
    .await
    .context("lock request")?
    .context("request not found")?;

    if row.requester_user_id == approver_user_id {
        bail!("self-approval forbidden");
    }

    let (level, next_on_approve) = match row.status {
        Status::PendingL1 => (ApprovalLevel::L1, Status::PendingL2),
        Status::PendingL2 => {
            let l1_approver = sqlx::query_scalar!(
                "select approver_user_id from request_approvals
                 where secret_request_id = $1 and level = 'L1'",
                id,
            )
            .fetch_optional(&mut *tx)
            .await
            .context("fetch L1 approver")?
            .context("L1 approval missing")?;

            if l1_approver == approver_user_id {
                bail!("L2 approver cannot also be L1 approver");
            }
            (ApprovalLevel::L2, Status::Approved)
        }
        Status::Approved | Status::Rejected => bail!("request already resolved"),
    };

    sqlx::query!(
        "insert into request_approvals
           (secret_request_id, level, decision, approver_user_id, approver_group, note)
         values ($1, $2, $3, $4, $5, $6)",
        id,
        level as ApprovalLevel,
        decision as Decision,
        approver_user_id,
        approver_group,
        note,
    )
    .execute(&mut *tx)
    .await
    .context("insert approval")?;

    let new_status = match decision {
        Decision::Approved => next_on_approve,
        Decision::Rejected => Status::Rejected,
    };
    let terminal = !matches!(new_status, Status::PendingL1 | Status::PendingL2);

    sqlx::query!(
        "update secret_requests
         set status = $1,
             resolved_at = case when $2 then now() else null end
         where secret_request_id = $3",
        new_status as Status,
        terminal,
        id,
    )
    .execute(&mut *tx)
    .await
    .context("update status")?;

    tx.commit().await.context("commit")
}
