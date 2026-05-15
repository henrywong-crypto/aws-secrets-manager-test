mod config;
mod database;

use anyhow::{Context, Result};
use axum::Router;
use axum::routing::get;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{error, info};

use crate::config::{build_app_state, load_config};
use crate::database::setup_database;

#[tokio::main]
async fn main() -> Result<()> {
    if dotenv::dotenv().is_err() {
        eprintln!("dotenv: no .env file loaded");
    }
    tracing_subscriber::fmt::init();

    let cfg = load_config().context("load config")?;
    let pool = setup_database(&cfg.database_url).await.context("database")?;
    sqlx::migrate!("../migrations")
        .run(&pool)
        .await
        .context("run migrations")?;

    let host = cfg.host.clone();
    let port = cfg.port;
    let app_state = build_app_state(cfg, pool).await.context("build app state")?;

    let app = Router::new()
        .route("/health", get(health))
        .with_state(app_state);

    let listener = TcpListener::bind((host.as_str(), port))
        .await
        .context("bind listener")?;
    info!(host = %host, port, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serve")
}

async fn health() -> &'static str {
    "ok"
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if signal::ctrl_c().await.is_err() {
            error!("failed to install Ctrl+C handler");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => {
                error!("failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c   => info!("received SIGINT"),
        _ = terminate => info!("received SIGTERM"),
    }
}
