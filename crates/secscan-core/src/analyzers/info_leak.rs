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

pub fn analyze_server(headers: &HeaderMap) -> HeaderCheck {
    let val = get_header(headers, "server");
    if val.is_empty() {
        HeaderCheck {
            key: "server".into(),
            header: "Server".into(),
            status: CheckStatus::Pass,
            code: "server.none".into(),
            params: BTreeMap::new(),
            value: String::new(),
            reason: "Server header is not exposed.".into(),
            issues: Vec::new(),
        }
    } else {
        HeaderCheck {
            key: "server".into(),
            header: "Server".into(),
            status: CheckStatus::Warn,
            code: "server.exposed".into(),
            params: BTreeMap::from([("value".into(), val.clone())]),
            value: val,
            reason: "Exposes web server software/version information.".into(),
            issues: vec!["server_banner".into()],
        }
    }
}

pub fn analyze_x_powered_by(headers: &HeaderMap) -> HeaderCheck {
    let val = get_header(headers, "x-powered-by");
    if val.is_empty() {
        HeaderCheck {
            key: "xpb".into(),
            header: "X-Powered-By".into(),
            status: CheckStatus::Pass,
            code: "xpb.none".into(),
            params: BTreeMap::new(),
            value: String::new(),
            reason: "X-Powered-By header is not exposed.".into(),
            issues: Vec::new(),
        }
    } else {
        HeaderCheck {
            key: "xpb".into(),
            header: "X-Powered-By".into(),
            status: CheckStatus::Warn,
            code: "xpb.exposed".into(),
            params: BTreeMap::from([("value".into(), val.clone())]),
            value: val,
            reason: "Exposes backend framework or runtime information.".into(),
            issues: vec!["framework_banner".into()],
        }
    }
}

pub fn analyze_extra_info_leak(headers: &HeaderMap) -> HeaderCheck {
    let leak_headers = [
        ("x-aspnet-version", "X-AspNet-Version"),
        ("x-aspnetmvc-version", "X-AspNetMvc-Version"),
        ("x-generator", "X-Generator"),
        ("via", "Via"),
    ];

    let mut found = Vec::new();
    for (lower, display) in leak_headers {
        let val = get_header(headers, lower);
        if !val.is_empty() {
            found.push(format!("{display}: {val}"));
        }
    }

    if found.is_empty() {
        HeaderCheck {
            key: "infoLeak".into(),
            header: "Tech Disclosure Headers".into(),
            status: CheckStatus::Pass,
            code: "info_leak.none".into(),
            params: BTreeMap::new(),
            value: String::new(),
            reason: "No extra technology disclosure headers (AspNet/Via/X-Generator) found.".into(),
            issues: Vec::new(),
        }
    } else {
        HeaderCheck {
            key: "infoLeak".into(),
            header: "Tech Disclosure Headers".into(),
            status: CheckStatus::Warn,
            code: "info_leak.exposed".into(),
            params: BTreeMap::from([("count".into(), found.len().to_string())]),
            value: found.join(" | "),
            reason: format!(
                "Additional technology headers exposed: {}",
                found.join(", ")
            ),
            issues: found,
        }
    }
}
