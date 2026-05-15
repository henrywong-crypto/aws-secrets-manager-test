use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Group {
    pub group_id:    Uuid,
    pub group_name:  String,
    pub description: Option<String>,
    pub created_at:  DateTime<Utc>,
}

pub async fn create_group(
    pool: &PgPool,
    name: &str,
    description: Option<&str>,
) -> Result<Uuid> {
    sqlx::query_scalar!(
        "insert into groups (group_name, description) values ($1, $2) returning group_id",
        name,
        description,
    )
    .fetch_one(pool)
    .await
    .context("insert group")
}

pub async fn delete_group(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query!("delete from groups where group_id = $1", id)
        .execute(pool)
        .await
        .context("delete group")?;
    Ok(())
}

pub async fn list_groups(pool: &PgPool) -> Result<Vec<Group>> {
    sqlx::query_as!(
        Group,
        "select group_id, group_name, description, created_at from groups order by group_name",
    )
    .fetch_all(pool)
    .await
    .context("list groups")
}

pub async fn get_group(pool: &PgPool, id: Uuid) -> Result<Option<Group>> {
    sqlx::query_as!(
        Group,
        "select group_id, group_name, description, created_at
         from groups where group_id = $1",
        id,
    )
    .fetch_optional(pool)
    .await
    .context("get group")
}

pub async fn get_group_by_name(pool: &PgPool, name: &str) -> Result<Option<Group>> {
    sqlx::query_as!(
        Group,
        "select group_id, group_name, description, created_at
         from groups where group_name = $1",
        name,
    )
    .fetch_optional(pool)
    .await
    .context("get group by name")
}

pub async fn add_member(pool: &PgPool, user_id: Uuid, group_id: Uuid) -> Result<()> {
    sqlx::query!(
        "insert into user_group_memberships (user_id, group_id) values ($1, $2)
         on conflict (user_id, group_id) do nothing",
        user_id,
        group_id,
    )
    .execute(pool)
    .await
    .context("add member")?;
    Ok(())
}

pub async fn remove_member(pool: &PgPool, user_id: Uuid, group_id: Uuid) -> Result<()> {
    sqlx::query!(
        "delete from user_group_memberships where user_id = $1 and group_id = $2",
        user_id,
        group_id,
    )
    .execute(pool)
    .await
    .context("remove member")?;
    Ok(())
}

pub async fn is_member(pool: &PgPool, user_id: Uuid, group_id: Uuid) -> Result<bool> {
    sqlx::query_scalar!(
        r#"select exists(
              select 1 from user_group_memberships
              where user_id = $1 and group_id = $2
           ) as "exists!""#,
        user_id,
        group_id,
    )
    .fetch_one(pool)
    .await
    .context("is_member")
}

pub async fn list_members(pool: &PgPool, group_id: Uuid) -> Result<Vec<Uuid>> {
    sqlx::query_scalar!(
        "select user_id from user_group_memberships where group_id = $1 order by created_at",
        group_id,
    )
    .fetch_all(pool)
    .await
    .context("list members")
}

pub async fn list_groups_for_user(pool: &PgPool, user_id: Uuid) -> Result<Vec<Group>> {
    sqlx::query_as!(
        Group,
        "select g.group_id, g.group_name, g.description, g.created_at
         from groups g
         join user_group_memberships m on m.group_id = g.group_id
         where m.user_id = $1
         order by g.group_name",
        user_id,
    )
    .fetch_all(pool)
    .await
    .context("list groups for user")
}
