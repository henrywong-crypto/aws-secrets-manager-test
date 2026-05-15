use std::collections::HashMap;
use std::sync::Arc;

use aws_sdk_kms::Client as KmsClient;
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use sqlx::PgPool;

pub use myerrors::AppError;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: Arc<PgPool>,
    pub kms_client: KmsClient,
    pub kms_key_arn: String,
    pub sm_clients: Arc<HashMap<String, SecretsManagerClient>>,
    pub l2_approver_group: String,
    pub prefix_policies: Arc<Vec<PrefixPolicy>>,
}

#[derive(Clone, Debug)]
pub struct PrefixPolicy {
    pub prefix: String,
    pub aws_account_id: String,
    pub aws_region: String,
    pub allowed_group: String,
    pub l1_approver_group: String,
    pub tags: HashMap<String, String>,
}

impl AppState {
    pub fn lookup_prefix(&self, secret_name: &str) -> Option<&PrefixPolicy> {
        self.prefix_policies
            .iter()
            .find(|p| secret_name.starts_with(&p.prefix))
    }

    pub fn sm_client_for(&self, account_id: &str) -> Option<&SecretsManagerClient> {
        self.sm_clients.get(account_id)
    }
}
