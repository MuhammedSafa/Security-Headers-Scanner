use crate::analyzers::csp::parse_csp_directives;
use crate::model::{CheckStatus, HeaderCheck};
use http::HeaderMap;
use std::collections::BTreeMap;

pub fn analyze_clickjacking(headers: &HeaderMap) -> HeaderCheck {
    let csp_combined = headers
        .get_all("content-security-policy")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");

    let directives = parse_csp_directives(&csp_combined);
    if let Some(fa_vals) = directives.get("frame-ancestors") {
        let joined = if fa_vals.is_empty() {
            "frame-ancestors".to_string()
        } else {
            format!("frame-ancestors {}", fa_vals.join(" "))
        };
        let is_wildcard = fa_vals.iter().any(|v| {
            v == "*"
                || v == "'*'"
                || v.eq_ignore_ascii_case("http:")
                || v.eq_ignore_ascii_case("https:")
        });

        if is_wildcard || fa_vals.is_empty() {
            return HeaderCheck {
                key: "click".into(),
                header: "CSP frame-ancestors".into(),
                status: CheckStatus::Fail,
                code: "click.frame_ancestors_broad".into(),
                params: BTreeMap::new(),
                value: joined,
                reason: "CSP frame-ancestors allows broad/wildcard framing; clickjacking risk."
                    .into(),
                issues: vec!["wildcard_frame_ancestors".into()],
            };
        }

        return HeaderCheck {
            key: "click".into(),
            header: "CSP frame-ancestors".into(),
            status: CheckStatus::Pass,
            code: "click.frame_ancestors_ok".into(),
            params: BTreeMap::new(),
            value: joined,
            reason: "Framing is restricted via CSP frame-ancestors.".into(),
            issues: Vec::new(),
        };
    }

    let xfo = headers
        .get("x-frame-options")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("");

    if !xfo.is_empty() {
        let upper = xfo.to_ascii_uppercase();
        if upper == "DENY" || upper == "SAMEORIGIN" {
            return HeaderCheck {
                key: "click".into(),
                header: "X-Frame-Options".into(),
                status: CheckStatus::Pass,
                code: "click.xfo_ok".into(),
                params: BTreeMap::from([("value".into(), upper.clone())]),
                value: upper,
                reason: "Framing is restricted via X-Frame-Options.".into(),
                issues: Vec::new(),
            };
        }

        return HeaderCheck {
            key: "click".into(),
            header: "X-Frame-Options".into(),
            status: CheckStatus::Warn,
            code: "click.xfo_weak".into(),
            params: BTreeMap::from([("value".into(), xfo.into())]),
            value: xfo.into(),
            reason: format!("Non-standard or deprecated X-Frame-Options value: {xfo}."),
            issues: vec!["weak_xfo".into()],
        };
    }

    HeaderCheck {
        key: "click".into(),
        header: "Clickjacking Protection".into(),
        status: CheckStatus::Fail,
        code: "click.missing".into(),
        params: BTreeMap::new(),
        value: String::new(),
        reason: "Neither CSP frame-ancestors nor X-Frame-Options is configured.".into(),
        issues: vec!["missing".into()],
    }
}
