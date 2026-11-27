use crate::model::{CheckStatus, HeaderCheck};
use http::HeaderMap;
use std::collections::BTreeMap;

fn get_header(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

pub fn analyze_xcto(headers: &HeaderMap) -> HeaderCheck {
    let val = get_header(headers, "x-content-type-options");
    if val.eq_ignore_ascii_case("nosniff") {
        HeaderCheck {
            key: "xcto".into(),
            header: "X-Content-Type-Options".into(),
            status: CheckStatus::Pass,
            code: "xcto.ok".into(),
            params: BTreeMap::new(),
            value: val,
            reason: "MIME sniffing is prevented with nosniff.".into(),
            issues: Vec::new(),
        }
    } else {
        HeaderCheck {
            key: "xcto".into(),
            header: "X-Content-Type-Options".into(),
            status: CheckStatus::Fail,
            code: "xcto.missing".into(),
            params: BTreeMap::new(),
            value: val,
            reason: "X-Content-Type-Options should be set to nosniff.".into(),
            issues: vec!["missing_nosniff".into()],
        }
    }
}

pub fn analyze_referrer_policy(headers: &HeaderMap) -> HeaderCheck {
    let raw = get_header(headers, "referrer-policy");
    if raw.is_empty() {
        return HeaderCheck {
            key: "referrerPolicy".into(),
            header: "Referrer-Policy".into(),
            status: CheckStatus::Fail,
            code: "referrer.missing".into(),
            params: BTreeMap::new(),
            value: String::new(),
            reason: "Referrer-Policy header is missing.".into(),
            issues: vec!["missing".into()],
        };
    }

    // Multiple comma-separated fallback tokens are valid; evaluate the last token.
    let effective = raw
        .split(',')
        .map(str::trim)
        .rfind(|s| !s.is_empty())
        .unwrap_or("")
        .to_ascii_lowercase();

    let safe = [
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    ];

    if safe.contains(&effective.as_str()) {
        HeaderCheck {
            key: "referrerPolicy".into(),
            header: "Referrer-Policy".into(),
            status: CheckStatus::Pass,
            code: "referrer.ok".into(),
            params: BTreeMap::from([("value".into(), effective)]),
            value: raw,
            reason: "Recommended Referrer-Policy configured.".into(),
            issues: Vec::new(),
        }
    } else {
        HeaderCheck {
            key: "referrerPolicy".into(),
            header: "Referrer-Policy".into(),
            status: CheckStatus::Warn,
            code: "referrer.weak".into(),
            params: BTreeMap::from([("value".into(), effective.clone())]),
            value: raw,
            reason: format!("Consider a stricter Referrer-Policy (current: {effective})."),
            issues: vec!["weak_referrer_policy".into()],
        }
    }
}

pub fn analyze_permissions_policy(headers: &HeaderMap) -> HeaderCheck {
    let val = get_header(headers, "permissions-policy");
    if !val.is_empty() {
        HeaderCheck {
            key: "perm".into(),
            header: "Permissions-Policy".into(),
            status: CheckStatus::Pass,
            code: "perm.ok".into(),
            params: BTreeMap::new(),
            value: val,
            reason: "Browser features are restricted via Permissions-Policy.".into(),
            issues: Vec::new(),
        }
    } else {
        HeaderCheck {
            key: "perm".into(),
            header: "Permissions-Policy".into(),
            status: CheckStatus::Fail,
            code: "perm.missing".into(),
            params: BTreeMap::new(),
            value: String::new(),
            reason: "Permissions-Policy header is missing.".into(),
            issues: vec!["missing".into()],
        }
    }
}

pub fn analyze_coop(headers: &HeaderMap) -> HeaderCheck {
    let val = get_header(headers, "cross-origin-opener-policy");
    let lower = val.to_ascii_lowercase();
    if lower == "same-origin" || lower == "same-origin-allow-popups" {
        HeaderCheck {
            key: "coop".into(),
            header: "Cross-Origin-Opener-Policy".into(),
            status: CheckStatus::Pass,
            code: "coop.ok".into(),
            params: BTreeMap::from([("value".into(), val.clone())]),
            value: val,
            reason: "Browsing context isolation configured.".into(),
            issues: Vec::new(),
        }
    } else if val.is_empty() {
        HeaderCheck {
            key: "coop".into(),
            header: "Cross-Origin-Opener-Policy".into(),
            status: CheckStatus::Warn,
            code: "coop.missing".into(),
            params: BTreeMap::new(),
            value: String::new(),
            reason: "Missing; same-origin is recommended for browsing context isolation.".into(),
            issues: vec!["missing".into()],
        }
    } else {
        HeaderCheck {
            key: "coop".into(),
            header: "Cross-Origin-Opener-Policy".into(),
            status: CheckStatus::Warn,
            code: "coop.weak".into(),
            params: BTreeMap::from([("value".into(), val.clone())]),
            value: val,
            reason: "Permissive Cross-Origin-Opener-Policy value; same-origin recommended.".into(),
            issues: vec!["weak_coop".into()],
        }
    }
}

pub fn analyze_coep(headers: &HeaderMap) -> HeaderCheck {
    let val = get_header(headers, "cross-origin-embedder-policy");
    let lower = val.to_ascii_lowercase();
    if lower == "require-corp" || lower == "credentialless" {
        HeaderCheck {
            key: "coep".into(),
            header: "Cross-Origin-Embedder-Policy".into(),
            status: CheckStatus::Pass,
            code: "coep.ok".into(),
            params: BTreeMap::from([("value".into(), val.clone())]),
            value: val,
            reason: "Cross-origin embedder isolation configured.".into(),
            issues: Vec::new(),
        }
    } else if val.is_empty() {
        HeaderCheck {
            key: "coep".into(),
            header: "Cross-Origin-Embedder-Policy".into(),
            status: CheckStatus::Info,
            code: "coep.missing".into(),
            params: BTreeMap::new(),
            value: String::new(),
            reason: "Not set; optional unless cross-origin isolation is needed (require-corp / credentialless).".into(),
            issues: Vec::new(),
        }
    } else {
        HeaderCheck {
            key: "coep".into(),
            header: "Cross-Origin-Embedder-Policy".into(),
            status: CheckStatus::Warn,
            code: "coep.weak".into(),
            params: BTreeMap::from([("value".into(), val.clone())]),
            value: val,
            reason: "Non-strict Cross-Origin-Embedder-Policy value.".into(),
            issues: vec!["weak_coep".into()],
        }
    }
}

pub fn analyze_corp(headers: &HeaderMap) -> HeaderCheck {
    let val = get_header(headers, "cross-origin-resource-policy");
    let lower = val.to_ascii_lowercase();
    if lower == "same-origin" || lower == "same-site" {
        HeaderCheck {
            key: "corp".into(),
            header: "Cross-Origin-Resource-Policy".into(),
            status: CheckStatus::Pass,
            code: "corp.ok".into(),
            params: BTreeMap::from([("value".into(), val.clone())]),
            value: val,
            reason: "Cross-origin resource sharing is restricted.".into(),
            issues: Vec::new(),
        }
    } else if val.is_empty() {
        HeaderCheck {
            key: "corp".into(),
            header: "Cross-Origin-Resource-Policy".into(),
            status: CheckStatus::Warn,
            code: "corp.missing".into(),
            params: BTreeMap::new(),
            value: String::new(),
            reason: "Missing; same-origin or same-site is recommended.".into(),
            issues: vec!["missing".into()],
        }
    } else {
        HeaderCheck {
            key: "corp".into(),
            header: "Cross-Origin-Resource-Policy".into(),
            status: CheckStatus::Info,
            code: "corp.cross_origin".into(),
            params: BTreeMap::from([("value".into(), val.clone())]),
            value: val,
            reason: "Resource explicitly allows cross-origin loading.".into(),
            issues: Vec::new(),
        }
    }
}

pub fn analyze_acao(headers: &HeaderMap) -> HeaderCheck {
    let val = get_header(headers, "access-control-allow-origin");
    let creds =
        get_header(headers, "access-control-allow-credentials").eq_ignore_ascii_case("true");

    if val.is_empty() {
        HeaderCheck {
            key: "acao".into(),
            header: "Access-Control-Allow-Origin".into(),
            status: CheckStatus::Info,
            code: "acao.none".into(),
            params: BTreeMap::new(),
            value: String::new(),
            reason: "Not set; default Same-Origin Policy applies.".into(),
            issues: Vec::new(),
        }
    } else if val == "*" && creds {
        HeaderCheck {
            key: "acao".into(),
            header: "Access-Control-Allow-Origin".into(),
            status: CheckStatus::Fail,
            code: "acao.wildcard_credentials".into(),
            params: BTreeMap::new(),
            value: val,
            reason: "Wildcard (*) combined with Access-Control-Allow-Credentials: true.".into(),
            issues: vec!["wildcard_with_credentials".into()],
        }
    } else if val == "*" {
        HeaderCheck {
            key: "acao".into(),
            header: "Access-Control-Allow-Origin".into(),
            status: CheckStatus::Warn,
            code: "acao.wildcard".into(),
            params: BTreeMap::new(),
            value: val,
            reason: "Open to all origins (*); verify this endpoint is intentionally public.".into(),
            issues: vec!["wildcard_origin".into()],
        }
    } else {
        HeaderCheck {
            key: "acao".into(),
            header: "Access-Control-Allow-Origin".into(),
            status: CheckStatus::Pass,
            code: "acao.restricted".into(),
            params: BTreeMap::from([("value".into(), val.clone())]),
            value: val,
            reason: "CORS restricted to a specific origin.".into(),
            issues: Vec::new(),
        }
    }
}

pub fn analyze_xxss(headers: &HeaderMap) -> HeaderCheck {
    let val = get_header(headers, "x-xss-protection");
    let lower = val.to_ascii_lowercase();
    if lower.is_empty() {
        HeaderCheck {
            key: "xxss".into(),
            header: "X-XSS-Protection".into(),
            status: CheckStatus::Pass,
            code: "xxss.absent".into(),
            params: BTreeMap::new(),
            value: String::new(),
            reason: "Not set; deprecated in modern browsers (use CSP instead).".into(),
            issues: Vec::new(),
        }
    } else if lower == "0" {
        HeaderCheck {
            key: "xxss".into(),
            header: "X-XSS-Protection".into(),
            status: CheckStatus::Pass,
            code: "xxss.disabled".into(),
            params: BTreeMap::new(),
            value: val,
            reason: "Explicitly disabled (0); modern best practice alongside CSP.".into(),
            issues: Vec::new(),
        }
    } else if lower.starts_with('1') {
        HeaderCheck {
            key: "xxss".into(),
            header: "X-XSS-Protection".into(),
            status: CheckStatus::Warn,
            code: "xxss.deprecated".into(),
            params: BTreeMap::from([("value".into(), val.clone())]),
            value: val,
            reason:
                "Legacy XSS auditor enabled; deprecated and can introduce leaks (set 0 or remove)."
                    .into(),
            issues: vec!["deprecated_enabled".into()],
        }
    } else {
        HeaderCheck {
            key: "xxss".into(),
            header: "X-XSS-Protection".into(),
            status: CheckStatus::Fail,
            code: "xxss.invalid".into(),
            params: BTreeMap::from([("value".into(), val.clone())]),
            value: val,
            reason: "Invalid X-XSS-Protection header value.".into(),
            issues: vec!["invalid_value".into()],
        }
    }
}
