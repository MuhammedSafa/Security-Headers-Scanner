use crate::model::{CheckStatus, HeaderCheck};
use http::HeaderMap;
use std::collections::BTreeMap;

pub fn analyze_cookies(headers: &HeaderMap) -> HeaderCheck {
    let cookies: Vec<&str> = headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    if cookies.is_empty() {
        return HeaderCheck {
            key: "cookies".into(),
            header: "Set-Cookie".into(),
            status: CheckStatus::Info,
            code: "cookies.none".into(),
            params: BTreeMap::new(),
            value: String::new(),
            reason: "No cookies set in response.".into(),
            issues: Vec::new(),
        };
    }

    let mut issues = Vec::new();
    for raw in &cookies {
        let mut parts = raw.split(';').map(str::trim);
        let name_val = parts.next().unwrap_or("");
        let name = name_val
            .split('=')
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("(unnamed)");

        let mut has_secure = false;
        let mut has_httponly = false;
        let mut samesite: Option<String> = None;

        for attr in parts {
            let lower = attr.to_ascii_lowercase();
            if lower == "secure" {
                has_secure = true;
            } else if lower == "httponly" {
                has_httponly = true;
            } else if let Some(val) = lower.strip_prefix("samesite=") {
                samesite = Some(val.trim().to_string());
            }
        }

        if !has_secure {
            issues.push(format!("{name}: missing Secure"));
        }
        if !has_httponly {
            issues.push(format!("{name}: missing HttpOnly"));
        }
        match samesite.as_deref() {
            Some("strict") | Some("lax") => {}
            Some("none") => {
                if !has_secure {
                    issues.push(format!("{name}: SameSite=None requires Secure"));
                }
            }
            Some(other) => {
                issues.push(format!("{name}: invalid SameSite={other}"));
            }
            None => {
                issues.push(format!("{name}: missing SameSite"));
            }
        }
    }

    let mut params = BTreeMap::new();
    params.insert("cookieCount".into(), cookies.len().to_string());
    params.insert("issueCount".into(), issues.len().to_string());

    if issues.is_empty() {
        HeaderCheck {
            key: "cookies".into(),
            header: "Set-Cookie".into(),
            status: CheckStatus::Pass,
            code: "cookies.ok".into(),
            params,
            value: cookies.join("\n"),
            reason: format!(
                "All {} cookie(s) set Secure, HttpOnly, and valid SameSite.",
                cookies.len()
            ),
            issues: Vec::new(),
        }
    } else {
        HeaderCheck {
            key: "cookies".into(),
            header: "Set-Cookie".into(),
            status: CheckStatus::Fail,
            code: "cookies.insecure".into(),
            params,
            value: cookies.join("\n"),
            reason: issues.join(" | "),
            issues,
        }
    }
}
