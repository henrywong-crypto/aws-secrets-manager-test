use anyhow::{Context, Result};
use sqlx::PgPool;
use uuid::Uuid;

pub async fn create_user(pool: &PgPool, email: &str) -> Result<()> {
    sqlx::query!(
        "insert into users (user_email) values ($1)
         on conflict (user_email) do nothing",
        email.to_lowercase()
    )
    .execute(pool)
    .await
    .context("insert user")?;
    Ok(())
}

pub async fn get_user_id(pool: &PgPool, email: &str) -> Result<Uuid> {
    sqlx::query_scalar!(
        "select user_id from users where user_email = $1",
        email.to_lowercase()
    )
    .fetch_one(pool)
    .await
    .context("fetch user_id")
}
