use crate::analyzers::{analyze_all, extract_raw_headers};
use crate::config::ScanConfig;
use crate::model::{RedirectHop, ScanResult};
use crate::remediation::build_remediations;
use crate::scorer::compute_score;
use crate::ssrf::{validate_url, SsrfError, SsrfSafeResolver};
use futures::stream::{self, StreamExt};
use http::HeaderMap;
use reqwest::redirect::Policy;
use reqwest::Client;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("Invalid domain or URL")]
    InvalidUrl,
    #[error(transparent)]
    Ssrf(#[from] SsrfError),
    #[error("Too many redirects (max {0})")]
    TooManyRedirects(usize),
    #[error("Request timed out")]
    Timeout,
    #[error("HTTP request failed: {0}")]
    Request(String),
}

impl FetchError {
    pub fn code(&self) -> &'static str {
        match self {
            FetchError::InvalidUrl => "error.invalid_url",
            FetchError::Ssrf(_) => "error.ssrf_blocked",
            FetchError::TooManyRedirects(_) => "error.too_many_redirects",
            FetchError::Timeout => "error.timeout",
            FetchError::Request(_) => "error.network",
        }
    }
}

#[derive(Debug, Clone)]
pub struct NormalizedTarget {
    pub url: Url,
    pub explicit_scheme: bool,
}

/// Normalizes a user-supplied domain or URL while preserving any explicit path/query.
pub fn normalize_input(input: &str) -> Result<NormalizedTarget, FetchError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(FetchError::InvalidUrl);
    }

    let explicit_scheme = trimmed.contains("://");
    let candidate = if explicit_scheme {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };

    let url = Url::parse(&candidate).map_err(|_| FetchError::InvalidUrl)?;
    if url.host().is_none() {
        return Err(FetchError::InvalidUrl);
    }
    Ok(NormalizedTarget {
        url,
        explicit_scheme,
    })
}

struct FetchOutcome {
    status: u16,
    final_url: String,
    headers: HeaderMap,
    redirect_chain: Vec<RedirectHop>,
    http_redirected_to_https: bool,
}

#[derive(Clone)]
pub struct Scanner {
    client: Client,
    config: ScanConfig,
}

impl Scanner {
    pub fn new(config: ScanConfig) -> Result<Self, reqwest::Error> {
        let resolver = Arc::new(SsrfSafeResolver {
            allow_private_networks: config.allow_private_networks,
        });

        let client = Client::builder()
            .dns_resolver(resolver)
            .redirect(Policy::none())
            .pool_idle_timeout(Duration::from_secs(10))
            .connect_timeout(config.hop_timeout)
            .user_agent(&config.user_agent)
            .danger_accept_invalid_certs(config.allow_self_signed_tls)
            .build()?;

        Ok(Self { client, config })
    }

    pub fn config(&self) -> &ScanConfig {
        &self.config
    }

    pub async fn scan_one(&self, domain: &str) -> ScanResult {
        let started = Instant::now();
        let target = match normalize_input(domain) {
            Ok(t) => t,
            Err(e) => {
                return ScanResult::failure(
                    domain,
                    e.code(),
                    e.to_string(),
                    started.elapsed().as_millis() as u64,
                );
            }
        };

        if let Err(e) = validate_url(&target.url, self.config.allow_private_networks) {
            return ScanResult::failure(
                domain,
                "error.ssrf_blocked",
                e.to_string(),
                started.elapsed().as_millis() as u64,
            );
        }

        let outcome = match self.fetch_with_fallback(&target).await {
            Ok(o) => o,
            Err(e) => {
                return ScanResult::failure(
                    domain,
                    e.code(),
                    e.to_string(),
                    started.elapsed().as_millis() as u64,
                );
            }
        };

        let duration_ms = started.elapsed().as_millis() as u64;
        let https_enforced = outcome.final_url.starts_with("https://");
        let (checks, summary) = analyze_all(&outcome.headers, &outcome.final_url);
        let (score, grade) = compute_score(&checks);
        let raw_headers = extract_raw_headers(&outcome.headers);
        let remediations = build_remediations(&checks);

        ScanResult {
            domain: domain.to_string(),
            ok: true,
            error: None,
            error_code: None,
            status: Some(outcome.status),
            final_url: Some(outcome.final_url),
            https_enforced,
            http_redirected_to_https: outcome.http_redirected_to_https,
            redirect_chain: outcome.redirect_chain,
            duration_ms,
            score: Some(score),
            grade: Some(grade),
            summary,
            checks,
            raw_headers,
            remediations,
        }
    }

    pub async fn scan_many(&self, domains: Vec<String>) -> Vec<ScanResult> {
        let concurrency = self.config.concurrency;
        stream::iter(domains)
            .map(|domain| {
                let scanner = self.clone();
                async move { scanner.scan_one(&domain).await }
            })
            .buffered(concurrency)
            .collect()
            .await
    }

    async fn fetch_with_fallback(
        &self,
        target: &NormalizedTarget,
    ) -> Result<FetchOutcome, FetchError> {
        let first_attempt = self.fetch_with_retry(&target.url).await;
        match first_attempt {
            Ok(outcome) => Ok(outcome),
            Err(FetchError::Ssrf(e)) => Err(FetchError::Ssrf(e)),
            Err(first_err) if !target.explicit_scheme && target.url.scheme() == "http" => {
                // HTTPS-only hosts often drop or refuse port 80; retry over HTTPS directly.
                let mut https_url = target.url.clone();
                let _ = https_url.set_scheme("https");
                self.fetch_with_retry(&https_url)
                    .await
                    .map_err(|_| first_err)
            }
            Err(err) => Err(err),
        }
    }

    async fn fetch_with_retry(&self, start_url: &Url) -> Result<FetchOutcome, FetchError> {
        let mut last_err = None;
        for attempt in 0..=self.config.retries {
            match tokio::time::timeout(self.config.global_timeout, self.follow_redirects(start_url))
                .await
            {
                Ok(Ok(outcome)) => return Ok(outcome),
                Ok(Err(FetchError::Ssrf(e))) => return Err(FetchError::Ssrf(e)),
                Ok(Err(FetchError::TooManyRedirects(n))) => {
                    return Err(FetchError::TooManyRedirects(n));
                }
                Ok(Err(e)) => last_err = Some(e),
                Err(_) => last_err = Some(FetchError::Timeout),
            }
            if attempt < self.config.retries {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
        Err(last_err.unwrap_or(FetchError::Timeout))
    }

    async fn follow_redirects(&self, start_url: &Url) -> Result<FetchOutcome, FetchError> {
        let mut current = start_url.clone();
        let started_http = start_url.scheme() == "http";
        let mut redirect_chain = Vec::new();

        for _ in 0..=self.config.max_redirects {
            validate_url(&current, self.config.allow_private_networks)?;

            let resp = self
                .client
                .get(current.clone())
                .timeout(self.config.hop_timeout)
                .header(
                    reqwest::header::ACCEPT,
                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                )
                .send()
                .await
                .map_err(classify_reqwest_error)?;

            let status = resp.status().as_u16();
            let headers = resp.headers().clone();
            let is_redirect = (300..400).contains(&status);
            let location = headers
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .map(ToOwned::to_owned);

            // Drop response immediately without reading the body.
            drop(resp);

            if is_redirect {
                if let Some(loc) = location {
                    if redirect_chain.len() >= self.config.max_redirects {
                        return Err(FetchError::TooManyRedirects(self.config.max_redirects));
                    }
                    redirect_chain.push(RedirectHop {
                        url: current.to_string(),
                        status,
                    });
                    current = current.join(&loc).map_err(|_| FetchError::InvalidUrl)?;
                    continue;
                }
            }

            let final_url = current.to_string();
            let http_redirected_to_https =
                started_http && !redirect_chain.is_empty() && final_url.starts_with("https://");

            return Ok(FetchOutcome {
                status,
                final_url,
                headers,
                redirect_chain,
                http_redirected_to_https,
            });
        }

        Err(FetchError::TooManyRedirects(self.config.max_redirects))
    }
}

fn classify_reqwest_error(err: reqwest::Error) -> FetchError {
    if err.is_timeout() {
        return FetchError::Timeout;
    }

    let mut chain = vec![err.to_string()];
    let mut current = std::error::Error::source(&err);
    while let Some(src) = current {
        chain.push(src.to_string());
        current = src.source();
    }
    let full = chain.join(": ");

    if full.contains("blocked private/internal IP") || full.contains("blocked by SSRF policy") {
        return FetchError::Ssrf(SsrfError::BlockedHost(
            chain.last().cloned().unwrap_or(full),
        ));
    }
    FetchError::Request(full)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_paths_and_normalizes_domains() {
        let a = normalize_input("example.com").unwrap();
        assert_eq!(a.url.as_str(), "http://example.com/");
        assert!(!a.explicit_scheme);

        let b = normalize_input("https://example.com/app/login?next=1").unwrap();
        assert_eq!(b.url.as_str(), "https://example.com/app/login?next=1");
        assert!(b.explicit_scheme);

        let c = normalize_input("example.com/dashboard").unwrap();
        assert_eq!(c.url.as_str(), "http://example.com/dashboard");
        assert!(!c.explicit_scheme);
    }

    #[tokio::test]
    async fn blocks_ssrf_targets_by_default() {
        let scanner = Scanner::new(ScanConfig::default()).unwrap();
        let res = scanner.scan_one("http://127.0.0.1:4000/").await;
        assert!(!res.ok);
        assert_eq!(res.error_code.as_deref(), Some("error.ssrf_blocked"));

        let meta = scanner
            .scan_one("http://169.254.169.254/latest/meta-data/")
            .await;
        assert!(!meta.ok);
        assert_eq!(meta.error_code.as_deref(), Some("error.ssrf_blocked"));
    }
}
