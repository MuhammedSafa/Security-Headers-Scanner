pub mod middleware;
pub mod openapi;
pub mod routes;

use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, Method};
use axum::middleware::from_fn;
use axum::routing::{get, post};
use axum::Router;
use middleware::security_headers_middleware;
use routes::{
    get_last_scan, get_last_scan_yaml, healthz, openapi_handler, post_diff, post_scan,
    post_scan_stream, AppState,
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

pub fn build_router(state: AppState, cors_origin: Option<&str>) -> Router {
    let cors = build_cors(cors_origin);

    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/healthz", get(healthz))
        .route("/api/openapi.json", get(openapi_handler))
        .route("/api/last-scan", get(get_last_scan))
        .route("/api/last-scan/yaml", get(get_last_scan_yaml))
        .route("/api/diff", post(post_diff))
        .route("/api/scan", post(post_scan))
        .route("/api/scan/stream", post(post_scan_stream))
        .with_state(state)
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024)) // 2 MB max payload
        .layer(cors)
        .layer(from_fn(security_headers_middleware))
        .layer(TraceLayer::new_for_http())
}

fn build_cors(cors_origin: Option<&str>) -> CorsLayer {
    let base = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([http::header::CONTENT_TYPE, http::header::ACCEPT]);

    match cors_origin.map(str::trim).filter(|s| !s.is_empty()) {
        Some("*") => base.allow_origin(tower_http::cors::Any),
        Some(list) => {
            let origins: Vec<HeaderValue> = list
                .split(',')
                .filter_map(|o| HeaderValue::from_str(o.trim()).ok())
                .collect();
            if origins.is_empty() {
                base
            } else {
                base.allow_origin(AllowOrigin::list(origins))
            }
        }
        None => base,
    }
}
