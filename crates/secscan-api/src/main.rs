use secscan_api::build_router;
use secscan_api::middleware::RateLimiter;
use secscan_api::routes::AppState;
use secscan_core::{ScanConfig, Scanner};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("secscan_api=info,secscan_core=info,tower_http=info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    let config = ScanConfig::from_env();
    let rate_limit: usize = env::var("RATE_LIMIT_PER_MINUTE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let cors_origin = env::var("CORS_ORIGIN").ok();
    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4000);

    let scanner = Scanner::new(config.clone())?;
    let state = AppState {
        scanner,
        rate_limiter: RateLimiter::new(rate_limit),
        snapshot_lock: Arc::new(Mutex::new(())),
    };

    let app = build_router(state, cors_origin.as_deref());
    let addr: SocketAddr = format!("{host}:{port}").parse()?;

    info!(
        %addr,
        concurrency = config.concurrency,
        allow_private = config.allow_private_networks,
        last_scan_path = %config.last_scan_path.display(),
        "secscan-api listening"
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("Graceful shutdown signal received");
}
