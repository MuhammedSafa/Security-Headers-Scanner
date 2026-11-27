pub mod clickjacking;
pub mod cookies;
pub mod csp;
pub mod headers;
pub mod hsts;
pub mod info_leak;

use crate::model::{CheckStatus, CheckSummary, HeaderCheck};
use http::HeaderMap;
use std::collections::BTreeMap;

/// Runs all security header analyzers on the response `headers` and returns the check map
/// alongside summary counts.
pub fn analyze_all(
    headers: &HeaderMap,
    final_url: &str,
) -> (BTreeMap<String, HeaderCheck>, CheckSummary) {
    let https_enforced = final_url.starts_with("https://");

    let list = vec![
        hsts::analyze_hsts(headers, https_enforced),
        clickjacking::analyze_clickjacking(headers),
        headers::analyze_xcto(headers),
        headers::analyze_referrer_policy(headers),
        csp::analyze_csp(headers),
        headers::analyze_permissions_policy(headers),
        headers::analyze_coop(headers),
        headers::analyze_coep(headers),
        headers::analyze_corp(headers),
        headers::analyze_acao(headers),
        cookies::analyze_cookies(headers),
        info_leak::analyze_server(headers),
        info_leak::analyze_x_powered_by(headers),
        info_leak::analyze_extra_info_leak(headers),
        headers::analyze_xxss(headers),
    ];

    let mut summary = CheckSummary::default();
    let mut map = BTreeMap::new();

    for check in list {
        match check.status {
            CheckStatus::Pass => summary.pass += 1,
            CheckStatus::Warn => summary.warn += 1,
            CheckStatus::Fail => summary.fail += 1,
            CheckStatus::Info => summary.info += 1,
        }
        map.insert(check.key.clone(), check);
    }

    (map, summary)
}

pub fn extract_raw_headers(headers: &HeaderMap) -> BTreeMap<String, Vec<String>> {
    let mut raw: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, val) in headers.iter() {
        let key = name.as_str().to_ascii_lowercase();
        let value = val.to_str().unwrap_or("<non-utf8>").to_string();
        raw.entry(key).or_default().push(value);
    }
    raw
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn analyzes_multiple_set_cookie_headers_accurately() {
        let mut h = HeaderMap::new();
        h.append(
            "set-cookie",
            HeaderValue::from_static("session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"),
        );
        h.append(
            "set-cookie",
            HeaderValue::from_static("prefs=dark; Path=/; SameSite=None"),
        );

        let check = cookies::analyze_cookies(&h);
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check
            .issues
            .iter()
            .any(|i| i.contains("prefs: missing Secure")));
        assert!(check
            .issues
            .iter()
            .any(|i| i.contains("prefs: missing HttpOnly")));
        assert!(check
            .issues
            .iter()
            .any(|i| i.contains("prefs: SameSite=None requires Secure")));
        assert!(!check.issues.iter().any(|i| i.contains("session:")));
    }

    #[test]
    fn analyzes_deep_csp_directives() {
        let mut h = HeaderMap::new();
        h.insert(
            "content-security-policy",
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'none'",
            ),
        );
        let check = csp::analyze_csp(&h);
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.issues.contains(&"script_unsafe_inline".to_string()));
        assert!(check.issues.contains(&"script_unsafe_eval".to_string()));
        assert!(check.issues.contains(&"missing_base_uri".to_string()));
    }

    #[test]
    fn strong_headers_all_pass() {
        let mut h = HeaderMap::new();
        h.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
        );
        h.insert(
            "content-security-policy",
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            ),
        );
        h.insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
        h.insert(
            "referrer-policy",
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        );
        h.insert(
            "permissions-policy",
            HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
        );
        h.insert(
            "cross-origin-opener-policy",
            HeaderValue::from_static("same-origin"),
        );
        h.insert(
            "cross-origin-embedder-policy",
            HeaderValue::from_static("require-corp"),
        );
        h.insert(
            "cross-origin-resource-policy",
            HeaderValue::from_static("same-origin"),
        );
        h.insert("x-xss-protection", HeaderValue::from_static("0"));

        let (checks, summary) = analyze_all(&h, "https://example.com/");
        assert_eq!(summary.fail, 0);
        assert_eq!(summary.warn, 0);
        assert_eq!(checks["hsts"].status, CheckStatus::Pass);
        assert_eq!(checks["csp"].status, CheckStatus::Pass);
        assert_eq!(checks["click"].status, CheckStatus::Pass);
    }
}
