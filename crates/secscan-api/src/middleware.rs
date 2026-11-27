use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct RateLimiter {
    max_requests: usize,
    window: Duration,
    buckets: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
}

impl RateLimiter {
    pub fn new(max_requests_per_minute: usize) -> Self {
        Self {
            max_requests: max_requests_per_minute.max(1),
            window: Duration::from_secs(60),
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut guard = self.buckets.lock().unwrap_or_else(|e| e.into_inner());

        // Periodically prune stale IP entries to keep memory bounded
        if guard.len() > 2_000 {
            guard.retain(|_, q| {
                while let Some(&front) = q.front() {
                    if now.duration_since(front) > self.window {
                        q.pop_front();
                    } else {
                        break;
                    }
                }
                !q.is_empty()
            });
        }

        let entry = guard.entry(key.to_string()).or_default();
        while let Some(&front) = entry.front() {
            if now.duration_since(front) > self.window {
                entry.pop_front();
            } else {
                break;
            }
        }

        if entry.len() >= self.max_requests {
            return false;
        }
        entry.push_back(now);
        true
    }
}

pub fn extract_client_ip(req_headers: &http::HeaderMap) -> String {
    if let Some(xff) = req_headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(first) = xff
            .split(',')
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return first.to_string();
        }
    }
    if let Some(xri) = req_headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return xri.to_string();
    }
    "unknown".to_string()
}

pub fn too_many_requests_response() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({
            "error": "Rate limit exceeded. Please wait before starting another scan.",
            "errorCode": "error.rate_limited"
        })),
    )
        .into_response()
}

/// Attaches hardened security headers to every API response.
pub async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();

    let pairs = [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "strict-origin-when-cross-origin"),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        ),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
        (
            "content-security-policy",
            "default-src 'none'; frame-ancestors 'none'",
        ),
        ("x-xss-protection", "0"),
    ];

    for (name, val) in pairs {
        if let (Ok(hname), Ok(hval)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(val),
        ) {
            headers.insert(hname, hval);
        }
    }

    res
}
