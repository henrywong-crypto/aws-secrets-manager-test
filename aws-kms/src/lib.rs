use anyhow::{Context, Result};
use aws_sdk_kms::Client;
use aws_sdk_kms::primitives::Blob;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

pub async fn encrypt(client: &Client, key_id: &str, plaintext: &str) -> Result<String> {
    let output = client
        .encrypt()
        .key_id(key_id)
        .plaintext(Blob::new(plaintext.as_bytes()))
        .send()
        .await
        .context("Encrypt")?;

    let ciphertext = output
        .ciphertext_blob()
        .context("Encrypt returned no ciphertext")?;

    Ok(STANDARD.encode(ciphertext.as_ref()))
}

pub async fn decrypt(client: &Client, ciphertext_b64: &str) -> Result<String> {
    let ciphertext = STANDARD
        .decode(ciphertext_b64)
        .context("decode base64 ciphertext")?;

    let output = client
        .decrypt()
        .ciphertext_blob(Blob::new(ciphertext))
        .send()
        .await
        .context("Decrypt")?;

    let plaintext = output
        .plaintext()
        .context("Decrypt returned no plaintext")?;

    String::from_utf8(plaintext.as_ref().to_vec()).context("KMS plaintext is not valid UTF-8")
}
