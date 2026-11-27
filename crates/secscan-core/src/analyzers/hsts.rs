use crate::model::{CheckStatus, HeaderCheck};
use http::HeaderMap;
use std::collections::BTreeMap;

const MIN_HSTS_SECONDS: u64 = 15_552_000; // 180 days
const RECOMMENDED_HSTS_SECONDS: u64 = 31_536_000; // 1 year

pub fn analyze_hsts(headers: &HeaderMap, https_enforced: bool) -> HeaderCheck {
    let raw = headers
        .get("strict-transport-security")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("");

    if !https_enforced {
        return HeaderCheck {
            key: "hsts".into(),
            header: "Strict-Transport-Security".into(),
            status: CheckStatus::Fail,
            code: "hsts.no_https".into(),
            params: BTreeMap::new(),
            value: raw.into(),
            reason: "Site does not enforce HTTPS; HSTS is ignored over plain HTTP.".into(),
            issues: vec!["no_https".into()],
        };
    }

    if raw.is_empty() {
        return HeaderCheck {
            key: "hsts".into(),
            header: "Strict-Transport-Security".into(),
            status: CheckStatus::Fail,
            code: "hsts.missing".into(),
            params: BTreeMap::new(),
            value: String::new(),
            reason: "Strict-Transport-Security header is missing (min 180 days recommended)."
                .into(),
            issues: vec!["missing".into()],
        };
    }

    let mut max_age: Option<u64> = None;
    let mut include_subdomains = false;
    let mut preload = false;

    for directive in raw.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        let lower = directive.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("max-age=") {
            let clean = rest.trim().trim_matches('"');
            if let Ok(val) = clean.parse::<u64>() {
                max_age = Some(val);
            }
        } else if lower == "includesubdomains" {
            include_subdomains = true;
        } else if lower == "preload" {
            preload = true;
        }
    }

    let mut params = BTreeMap::new();
    if let Some(age) = max_age {
        params.insert("maxAge".into(), age.to_string());
    }
    params.insert("includeSubDomains".into(), include_subdomains.to_string());
    params.insert("preload".into(), preload.to_string());

    match max_age {
        None => HeaderCheck {
            key: "hsts".into(),
            header: "Strict-Transport-Security".into(),
            status: CheckStatus::Fail,
            code: "hsts.invalid_max_age".into(),
            params,
            value: raw.into(),
            reason: "HSTS header is present but max-age is missing or invalid.".into(),
            issues: vec!["invalid_max_age".into()],
        },
        Some(0) => HeaderCheck {
            key: "hsts".into(),
            header: "Strict-Transport-Security".into(),
            status: CheckStatus::Fail,
            code: "hsts.disabled".into(),
            params,
            value: raw.into(),
            reason: "HSTS is disabled (max-age=0).".into(),
            issues: vec!["max_age_zero".into()],
        },
        Some(age) if age < MIN_HSTS_SECONDS => HeaderCheck {
            key: "hsts".into(),
            header: "Strict-Transport-Security".into(),
            status: CheckStatus::Warn,
            code: "hsts.short_max_age".into(),
            params,
            value: raw.into(),
            reason: format!(
                "HSTS max-age ({age}s) is below the 180-day minimum ({MIN_HSTS_SECONDS}s)."
            ),
            issues: vec!["short_max_age".into()],
        },
        Some(age) => {
            let mut notes = Vec::new();
            if !include_subdomains {
                notes.push("no_include_subdomains".to_string());
            }
            if preload && (!include_subdomains || age < RECOMMENDED_HSTS_SECONDS) {
                notes.push("preload_requirements_unmet".to_string());
            }

            if preload && (!include_subdomains || age < RECOMMENDED_HSTS_SECONDS) {
                HeaderCheck {
                    key: "hsts".into(),
                    header: "Strict-Transport-Security".into(),
                    status: CheckStatus::Warn,
                    code: "hsts.preload_incomplete".into(),
                    params,
                    value: raw.into(),
                    reason: "HSTS specifies preload without includeSubDomains and 1-year max-age."
                        .into(),
                    issues: notes,
                }
            } else if !include_subdomains {
                HeaderCheck {
                    key: "hsts".into(),
                    header: "Strict-Transport-Security".into(),
                    status: CheckStatus::Pass,
                    code: "hsts.ok_no_subdomains".into(),
                    params,
                    value: raw.into(),
                    reason: format!(
                        "HSTS max-age ({age}s) meets threshold; consider adding includeSubDomains."
                    ),
                    issues: notes,
                }
            } else {
                HeaderCheck {
                    key: "hsts".into(),
                    header: "Strict-Transport-Security".into(),
                    status: CheckStatus::Pass,
                    code: "hsts.strong".into(),
                    params,
                    value: raw.into(),
                    reason: format!("Strong HSTS policy (max-age={age}, includeSubDomains)."),
                    issues: Vec::new(),
                }
            }
        }
    }
}
