use axum::http::{HeaderValue, StatusCode};
use axum::routing::get;
use axum::Router;
use secscan_api::build_router;
use secscan_api::middleware::RateLimiter;
use secscan_api::routes::AppState;
use secscan_core::{ScanConfig, Scanner};
use serde_json::{json, Value};
use std::fs;
use std::sync::Arc;
use tokio::sync::Mutex;

async fn spawn_mock_target(strong_headers: bool) -> String {
    let app = Router::new().route(
        "/",
        get(move || async move {
            let mut resp = axum::response::Response::new(axum::body::Body::from("ok"));
            let h = resp.headers_mut();
            h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
            if strong_headers {
                h.insert("x-frame-options", HeaderValue::from_static("DENY"));
                h.insert(
                    "content-security-policy",
                    HeaderValue::from_static(
                        "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
                    ),
                );
                h.insert(
                    "referrer-policy",
                    HeaderValue::from_static("strict-origin-when-cross-origin"),
                );
                h.insert(
                    "permissions-policy",
                    HeaderValue::from_static("camera=(), microphone=()"),
                );
                h.insert(
                    "cross-origin-opener-policy",
                    HeaderValue::from_static("same-origin"),
                );
                h.insert(
                    "cross-origin-resource-policy",
                    HeaderValue::from_static("same-origin"),
                );
                h.append(
                    "set-cookie",
                    HeaderValue::from_static("sid=1; Path=/; Secure; HttpOnly; SameSite=Strict"),
                );
                h.append(
                    "set-cookie",
                    HeaderValue::from_static("theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax"),
                );
            } else {
                h.insert("server", HeaderValue::from_static("TestServer/1.0"));
                h.insert("x-powered-by", HeaderValue::from_static("LegacyPHP"));
                h.append(
                    "set-cookie",
                    HeaderValue::from_static("insecure=1; Path=/"),
                );
            }
            resp
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}/")
}

async fn spawn_api(allow_private: bool, rate_limit: usize) -> (String, std::path::PathBuf) {
    let yaml_path = std::env::temp_dir().join(format!(
        "secscan-api-it-{}.yaml",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    let _ = fs::remove_file(&yaml_path);

    let cfg = ScanConfig {
        allow_private_networks: allow_private,
        last_scan_path: yaml_path.clone(),
        ..Default::default()
    };

    let state = AppState {
        scanner: Scanner::new(cfg).unwrap(),
        rate_limiter: RateLimiter::new(rate_limit),
        snapshot_lock: Arc::new(Mutex::new(())),
    };
    let app = build_router(state, Some("*"));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), yaml_path)
}

#[tokio::test]
async fn healthz_and_security_headers_work() {
    let (api_base, yaml_path) = spawn_api(false, 30).await;
    let client = reqwest::Client::new();

    for path in ["/healthz", "/api/healthz"] {
        let resp = client
            .get(format!("{api_base}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            resp.headers()
                .get("x-frame-options")
                .and_then(|v| v.to_str().ok()),
            Some("DENY")
        );
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["ok"], true);
    }

    let _ = fs::remove_file(yaml_path);
}

#[tokio::test]
async fn ssrf_blocks_loopback_by_default_and_allows_when_opted_in() {
    let target = spawn_mock_target(true).await;
    let client = reqwest::Client::new();

    // Default: SSRF blocked
    let (api_blocked, yaml1) = spawn_api(false, 30).await;
    let r1: Value = client
        .post(format!("{api_blocked}/api/scan"))
        .json(&json!({ "domains": [target] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r1["results"][0]["ok"], false);
    assert_eq!(r1["results"][0]["errorCode"], "error.ssrf_blocked");

    // Opted in: ALLOW_PRIVATE_NETWORKS=true
    let (api_allowed, yaml2) = spawn_api(true, 30).await;
    let r2: Value = client
        .post(format!("{api_allowed}/api/scan"))
        .json(&json!({ "domains": [target] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r2["results"][0]["ok"], true);
    assert_eq!(r2["results"][0]["checks"]["cookies"]["status"], "pass");
    assert_eq!(r2["results"][0]["checks"]["csp"]["status"], "pass");

    let _ = fs::remove_file(yaml1);
    let _ = fs::remove_file(yaml2);
}

#[tokio::test]
async fn yaml_snapshot_and_sse_streaming_produce_diff() {
    let weak_target = spawn_mock_target(false).await;
    let strong_target = spawn_mock_target(true).await;
    let (api_base, yaml_path) = spawn_api(true, 30).await;
    let client = reqwest::Client::new();

    // 1st scan saves YAML snapshot
    let first: Value = client
        .post(format!("{api_base}/api/scan"))
        .json(&json!({ "domains": [weak_target] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(first.get("diff").is_none());
    assert!(yaml_path.exists());

    // Fetch raw YAML endpoint
    let yaml_resp = client
        .get(format!("{api_base}/api/last-scan/yaml"))
        .send()
        .await
        .unwrap();
    assert_eq!(yaml_resp.status(), StatusCode::OK);
    let yaml_text = yaml_resp.text().await.unwrap();
    assert!(yaml_text.contains("results:"));

    // 2nd scan via SSE streaming
    let sse_resp = client
        .post(format!("{api_base}/api/scan/stream"))
        .json(&json!({ "domains": [weak_target, strong_target] }))
        .send()
        .await
        .unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
    let sse_body = sse_resp.text().await.unwrap();
    assert!(sse_body.contains("event: start"));
    assert!(sse_body.contains("event: result"));
    assert!(sse_body.contains("event: done"));
    assert!(sse_body.contains("\"added\":1"));

    let _ = fs::remove_file(yaml_path);
}

#[tokio::test]
async fn rate_limiter_enforces_limit() {
    let (api_base, yaml_path) = spawn_api(false, 2).await;
    let client = reqwest::Client::new();

    for i in 0..3 {
        let resp = client
            .post(format!("{api_base}/api/scan"))
            .header("x-forwarded-for", "203.0.113.10")
            .json(&json!({ "domains": ["http://127.0.0.1/"] }))
            .send()
            .await
            .unwrap();
        if i < 2 {
            assert_eq!(resp.status(), StatusCode::OK);
        } else {
            assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }

    let _ = fs::remove_file(yaml_path);
}
