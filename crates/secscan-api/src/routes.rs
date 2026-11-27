use crate::middleware::{extract_client_ip, too_many_requests_response, RateLimiter};
use crate::openapi::openapi_spec;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures::stream::{self, StreamExt};
use secscan_core::{
    compute_diff, from_yaml, load_snapshot, save_snapshot, to_yaml, ScanDiff, ScanResult,
    ScanSnapshot, Scanner,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

#[derive(Clone)]
pub struct AppState {
    pub scanner: Scanner,
    pub rate_limiter: RateLimiter,
    pub snapshot_lock: Arc<Mutex<()>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRequest {
    pub domains: Vec<String>,
    #[serde(default = "default_true")]
    pub save_snapshot: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResponse {
    pub results: Vec<ScanResult>,
    pub snapshot: ScanSnapshot,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<ScanDiff>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffRequest {
    pub baseline_yaml: String,
    pub current: ScanSnapshot,
}

pub async fn healthz() -> impl IntoResponse {
    Json(json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION")
    }))
}

pub async fn openapi_handler() -> impl IntoResponse {
    Json(openapi_spec())
}

pub async fn get_last_scan(State(state): State<AppState>) -> Response {
    let _guard = state.snapshot_lock.lock().await;
    let path = &state.scanner.config().last_scan_path;
    match load_snapshot(path) {
        Ok(snapshot) => Json(json!({ "snapshot": snapshot })).into_response(),
        Err(e) => {
            warn!(error = %e, "Failed to read last-scan YAML");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": format!("Failed to read last-scan YAML: {e}"),
                    "errorCode": "error.snapshot_read"
                })),
            )
                .into_response()
        }
    }
}

pub async fn get_last_scan_yaml(State(state): State<AppState>) -> Response {
    let _guard = state.snapshot_lock.lock().await;
    let path = &state.scanner.config().last_scan_path;
    match load_snapshot(path) {
        Ok(Some(snapshot)) => match to_yaml(&snapshot) {
            Ok(yaml) => (
                StatusCode::OK,
                [(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/yaml; charset=utf-8"),
                )],
                yaml,
            )
                .into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response(),
        },
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "No previous scan YAML snapshot found",
                "errorCode": "error.no_snapshot"
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn post_diff(Json(req): Json<DiffRequest>) -> Response {
    match from_yaml(&req.baseline_yaml) {
        Ok(previous) => {
            let diff = compute_diff(&previous, &req.current);
            Json(json!({ "diff": diff, "previous": previous })).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("Invalid baseline YAML: {e}"),
                "errorCode": "error.invalid_yaml"
            })),
        )
            .into_response(),
    }
}

fn sanitize_domains(raw: Vec<String>, max: usize) -> Result<Vec<String>, Box<Response>> {
    let mut seen = HashSet::new();
    let mut cleaned = Vec::new();
    for item in raw {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            cleaned.push(trimmed.to_string());
        }
    }

    if cleaned.is_empty() {
        return Err(Box::new(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "At least one domain is required in domains[]",
                    "errorCode": "error.empty_domains"
                })),
            )
                .into_response(),
        ));
    }

    if cleaned.len() > max {
        return Err(Box::new(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!("Maximum {max} unique domains allowed per request (received {})", cleaned.len()),
                    "errorCode": "error.too_many_domains"
                })),
            )
                .into_response(),
        ));
    }

    Ok(cleaned)
}

pub async fn post_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ScanRequest>,
) -> Response {
    let ip = extract_client_ip(&headers);
    if !state.rate_limiter.check(&ip) {
        return too_many_requests_response();
    }

    let max = state.scanner.config().max_domains_per_request;
    let domains = match sanitize_domains(req.domains, max) {
        Ok(d) => d,
        Err(resp) => return *resp,
    };

    info!(client_ip = %ip, count = domains.len(), "Starting batch scan");

    let previous = {
        let _guard = state.snapshot_lock.lock().await;
        load_snapshot(&state.scanner.config().last_scan_path)
            .ok()
            .flatten()
    };

    let results = state.scanner.scan_many(domains).await;
    let snapshot = ScanSnapshot::from_results(results.clone());
    let diff = previous.as_ref().map(|prev| compute_diff(prev, &snapshot));

    if req.save_snapshot {
        let _guard = state.snapshot_lock.lock().await;
        if let Err(e) = save_snapshot(&state.scanner.config().last_scan_path, &snapshot) {
            error!(error = %e, "Failed to persist last-scan YAML");
        }
    }

    Json(ScanResponse {
        results,
        snapshot,
        diff,
    })
    .into_response()
}

pub async fn post_scan_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ScanRequest>,
) -> Response {
    let ip = extract_client_ip(&headers);
    if !state.rate_limiter.check(&ip) {
        return too_many_requests_response();
    }

    let max = state.scanner.config().max_domains_per_request;
    let domains = match sanitize_domains(req.domains, max) {
        Ok(d) => d,
        Err(resp) => return *resp,
    };

    let total = domains.len();
    let save_flag = req.save_snapshot;
    let concurrency = state.scanner.config().concurrency;
    info!(client_ip = %ip, count = total, "Starting SSE streaming scan");

    let previous = {
        let _guard = state.snapshot_lock.lock().await;
        load_snapshot(&state.scanner.config().last_scan_path)
            .ok()
            .flatten()
    };

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(64);

    tokio::spawn(async move {
        let start_payload = json!({ "total": total }).to_string();
        if tx
            .send(Ok(Event::default().event("start").data(start_payload)))
            .await
            .is_err()
        {
            return;
        }

        let scanner = state.scanner.clone();
        let mut results_stream = stream::iter(domains.into_iter().enumerate())
            .map(move |(index, domain)| {
                let sc = scanner.clone();
                async move { (index, sc.scan_one(&domain).await) }
            })
            .buffer_unordered(concurrency);

        let mut collected: Vec<(usize, ScanResult)> = Vec::with_capacity(total);
        let mut done = 0usize;

        while let Some((index, result)) = results_stream.next().await {
            done += 1;
            let payload = json!({
                "index": index,
                "done": done,
                "total": total,
                "result": result,
            })
            .to_string();

            collected.push((index, result));

            if tx
                .send(Ok(Event::default().event("result").data(payload)))
                .await
                .is_err()
            {
                // Client disconnected / aborted: stop scanning remaining domains.
                info!(
                    done,
                    total, "SSE client disconnected; aborting remaining scans"
                );
                return;
            }
        }

        // Preserve original request ordering in snapshot & diff
        collected.sort_by_key(|(idx, _)| *idx);
        let ordered_results: Vec<ScanResult> = collected.into_iter().map(|(_, r)| r).collect();
        let snapshot = ScanSnapshot::from_results(ordered_results);
        let diff = previous.as_ref().map(|prev| compute_diff(prev, &snapshot));

        if save_flag {
            let _guard = state.snapshot_lock.lock().await;
            if let Err(e) = save_snapshot(&state.scanner.config().last_scan_path, &snapshot) {
                error!(error = %e, "Failed to persist last-scan YAML after SSE scan");
            }
        }

        let done_payload = json!({
            "snapshot": snapshot,
            "diff": diff,
        })
        .to_string();
        let _ = tx
            .send(Ok(Event::default().event("done").data(done_payload)))
            .await;
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(10)))
        .into_response()
}
