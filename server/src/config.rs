use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use aws_config::BehaviorVersion;
use aws_config::sts::AssumeRoleProvider;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use myhandlers::{AppState, PrefixPolicy};
use serde::Deserialize;
use sqlx::PgPool;

#[derive(Clone, Debug, Deserialize)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub kms_key_arn: String,
    pub l2_approver_group: String,
    #[serde(default, rename = "prefix")]
    pub prefixes: Vec<PrefixConfig>,
    #[serde(default, rename = "aws_account")]
    pub aws_accounts: Vec<AccountConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PrefixConfig {
    pub prefix: String,
    pub aws_account_id: String,
    pub aws_region: String,
    pub allowed_group: String,
    pub l1_approver_group: String,
    #[serde(default)]
    pub tags: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AccountConfig {
    pub account_id: String,
    pub role_arn: String,
}

pub fn load_config() -> Result<AppConfig> {
    let cfg: AppConfig = config::Config::builder()
        .add_source(config::File::with_name("config").required(false))
        .add_source(config::Environment::default())
        .build()
        .context("build config")?
        .try_deserialize()
        .context("deserialize config")?;
    validate(&cfg)?;
    Ok(cfg)
}

fn validate(cfg: &AppConfig) -> Result<()> {
    if cfg.prefixes.is_empty() {
        bail!("at least one [[prefix]] is required");
    }

    let mut seen_prefix = HashSet::new();
    for p in &cfg.prefixes {
        if !seen_prefix.insert(&p.prefix) {
            bail!("duplicate [[prefix]] '{}'", p.prefix);
        }
    }

    let mut seen_account = HashSet::new();
    for a in &cfg.aws_accounts {
        if !seen_account.insert(&a.account_id) {
            bail!("duplicate [[aws_account]] '{}'", a.account_id);
        }
    }

    let accounts: HashSet<&String> = cfg.aws_accounts.iter().map(|a| &a.account_id).collect();
    for p in &cfg.prefixes {
        if !accounts.contains(&p.aws_account_id) {
            bail!(
                "[[prefix]] '{}' references aws_account_id '{}' with no [[aws_account]] entry",
                p.prefix,
                p.aws_account_id
            );
        }
    }

    Ok(())
}

pub async fn build_app_state(cfg: AppConfig, pool: PgPool) -> Result<AppState> {
    let base = aws_config::defaults(BehaviorVersion::latest()).load().await;
    let kms_client = KmsClient::new(&base);

    let mut sm_clients = HashMap::with_capacity(cfg.aws_accounts.len());
    for account in &cfg.aws_accounts {
        let provider = AssumeRoleProvider::builder(&account.role_arn)
            .session_name("aws-secrets-portal")
            .configure(&base)
            .build()
            .await;
        let sdk = aws_config::defaults(BehaviorVersion::latest())
            .credentials_provider(provider)
            .load()
            .await;
        sm_clients.insert(account.account_id.clone(), SecretsManagerClient::new(&sdk));
    }

    let mut prefix_policies: Vec<PrefixPolicy> = cfg
        .prefixes
        .into_iter()
        .map(|p| PrefixPolicy {
            prefix: p.prefix,
            aws_account_id: p.aws_account_id,
            aws_region: p.aws_region,
            allowed_group: p.allowed_group,
            l1_approver_group: p.l1_approver_group,
            tags: p.tags,
        })
        .collect();
    prefix_policies.sort_by(|a, b| b.prefix.len().cmp(&a.prefix.len()));

    Ok(AppState {
        db_pool: Arc::new(pool),
        kms_client,
        kms_key_arn: cfg.kms_key_arn,
        sm_clients: Arc::new(sm_clients),
        l2_approver_group: cfg.l2_approver_group,
        prefix_policies: Arc::new(prefix_policies),
    })
}
