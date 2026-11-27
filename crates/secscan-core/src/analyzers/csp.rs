use crate::model::{CheckStatus, HeaderCheck};
use http::HeaderMap;
use std::collections::BTreeMap;

/// Parses a Content-Security-Policy header into a directive map.
pub fn parse_csp_directives(raw: &str) -> BTreeMap<String, Vec<String>> {
    let mut map = BTreeMap::new();
    for segment in raw.split(';') {
        let trimmed = segment.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        if let Some(name) = parts.next() {
            let key = name.to_ascii_lowercase();
            let values: Vec<String> = parts.map(|s| s.to_string()).collect();
            map.entry(key).or_insert(values);
        }
    }
    map
}

pub fn analyze_csp(headers: &HeaderMap) -> HeaderCheck {
    let policies: Vec<&str> = headers
        .get_all("content-security-policy")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    if policies.is_empty() {
        let report_only = headers.contains_key("content-security-policy-report-only");
        if report_only {
            return HeaderCheck {
                key: "csp".into(),
                header: "Content-Security-Policy".into(),
                status: CheckStatus::Warn,
                code: "csp.report_only".into(),
                params: BTreeMap::new(),
                value: String::new(),
                reason: "Only Content-Security-Policy-Report-Only is set; policy is not enforced."
                    .into(),
                issues: vec!["report_only".into()],
            };
        }

        return HeaderCheck {
            key: "csp".into(),
            header: "Content-Security-Policy".into(),
            status: CheckStatus::Fail,
            code: "csp.missing".into(),
            params: BTreeMap::new(),
            value: String::new(),
            reason: "Content-Security-Policy header is missing.".into(),
            issues: vec!["missing".into()],
        };
    }

    let combined = policies.join("; ");
    let directives = parse_csp_directives(&combined);
    let mut issues = Vec::new();
    let mut high_risk = false;

    let default_src = directives.get("default-src");
    let script_src = directives.get("script-src").or(default_src);
    let object_src = directives.get("object-src").or(default_src);

    if let Some(vals) = default_src {
        if vals.iter().any(|v| v == "*") {
            issues.push("default_src_wildcard".into());
            high_risk = true;
        }
    }

    if let Some(vals) = script_src {
        let lower: Vec<String> = vals.iter().map(|v| v.to_ascii_lowercase()).collect();
        if lower.iter().any(|v| v == "*") {
            issues.push("script_src_wildcard".into());
            high_risk = true;
        }
        if lower.iter().any(|v| v == "'unsafe-inline'")
            && !lower.iter().any(|v| {
                v.starts_with("'nonce-") || v.starts_with("'sha") || v == "'strict-dynamic'"
            })
        {
            issues.push("script_unsafe_inline".into());
        }
        if lower.iter().any(|v| v == "'unsafe-eval'") {
            issues.push("script_unsafe_eval".into());
        }
        if lower
            .iter()
            .any(|v| v == "http:" || v.starts_with("http://"))
        {
            issues.push("script_http_source".into());
        }
        if lower.iter().any(|v| v == "data:") {
            issues.push("script_data_uri".into());
        }
    } else {
        issues.push("missing_script_or_default_src".into());
    }

    if let Some(vals) = object_src {
        if !vals.iter().any(|v| v.eq_ignore_ascii_case("'none'")) {
            issues.push("object_src_not_none".into());
        }
    } else {
        issues.push("missing_object_src".into());
    }

    if !directives.contains_key("base-uri") {
        issues.push("missing_base_uri".into());
    }

    let mut params = BTreeMap::new();
    params.insert("directiveCount".into(), directives.len().to_string());
    params.insert("issueCount".into(), issues.len().to_string());

    if high_risk {
        HeaderCheck {
            key: "csp".into(),
            header: "Content-Security-Policy".into(),
            status: CheckStatus::Warn,
            code: "csp.wildcard".into(),
            params,
            value: combined,
            reason: format!(
                "CSP is overly permissive (wildcard source detected: {}).",
                issues.join(", ")
            ),
            issues,
        }
    } else if issues.iter().any(|i| {
        matches!(
            i.as_str(),
            "script_unsafe_inline"
                | "script_unsafe_eval"
                | "script_http_source"
                | "script_data_uri"
                | "missing_script_or_default_src"
        )
    }) {
        HeaderCheck {
            key: "csp".into(),
            header: "Content-Security-Policy".into(),
            status: CheckStatus::Warn,
            code: "csp.weak_directives".into(),
            params,
            value: combined,
            reason: format!(
                "CSP has weakened script directives ({}).",
                issues.join(", ")
            ),
            issues,
        }
    } else if !issues.is_empty() {
        HeaderCheck {
            key: "csp".into(),
            header: "Content-Security-Policy".into(),
            status: CheckStatus::Pass,
            code: "csp.good_with_notes".into(),
            params,
            value: combined,
            reason: format!(
                "CSP is enforced; optional hardening: {}.",
                issues.join(", ")
            ),
            issues,
        }
    } else {
        HeaderCheck {
            key: "csp".into(),
            header: "Content-Security-Policy".into(),
            status: CheckStatus::Pass,
            code: "csp.strong".into(),
            params,
            value: combined,
            reason: "Strong Content-Security-Policy configured.".into(),
            issues: Vec::new(),
        }
    }
}
