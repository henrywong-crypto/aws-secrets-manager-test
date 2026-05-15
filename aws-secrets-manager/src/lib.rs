use std::collections::HashMap;

use anyhow::{Context, Result};
use aws_sdk_secretsmanager::Client;
use aws_sdk_secretsmanager::types::Tag;

pub async fn put_secret_value(
    client: &Client,
    name: &str,
    plaintext: &str,
    tags: &HashMap<String, String>,
) -> Result<()> {
    client
        .put_secret_value()
        .secret_id(name)
        .secret_string(plaintext)
        .send()
        .await
        .context("PutSecretValue")?;

    client
        .tag_resource()
        .secret_id(name)
        .set_tags((!tags.is_empty()).then(|| {
            tags.iter()
                .map(|(key, value)| Tag::builder().key(key).value(value).build())
                .collect()
        }))
        .send()
        .await
        .context("TagResource")?;

    Ok(())
}
