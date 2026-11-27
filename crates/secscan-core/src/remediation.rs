use crate::model::{CheckStatus, HeaderCheck, RemediationSnippet};
use std::collections::BTreeMap;

/// Generates actionable copy-paste remediation snippets for all `Warn` and `Fail` checks.
pub fn build_remediations(
    checks: &BTreeMap<String, HeaderCheck>,
) -> BTreeMap<String, RemediationSnippet> {
    let mut out = BTreeMap::new();
    for (key, check) in checks {
        if matches!(check.status, CheckStatus::Fail | CheckStatus::Warn) {
            if let Some(snippet) = snippet_for(key) {
                out.insert(key.clone(), snippet);
            }
        }
    }
    out
}

pub fn snippet_for(key: &str) -> Option<RemediationSnippet> {
    let snippet = match key {
        "hsts" => RemediationSnippet {
            title: "Strict-Transport-Security (HSTS)".into(),
            nginx: r#"add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;"#.into(),
            apache: r#"Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload""#.into(),
            express: r#"app.use(helmet.hsts({ maxAge: 63072000, includeSubDomains: true, preload: true }));"#.into(),
            cloudflare: r#"SSL/TLS -> Edge Certificates -> HTTP Strict Transport Security (HSTS): Enable, Max Age = 12 months, Include subdomains = On"#.into(),
        },
        "csp" => RemediationSnippet {
            title: "Content-Security-Policy (CSP)".into(),
            nginx: r#"add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" always;"#.into(),
            apache: r#"Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'""#.into(),
            express: r#"app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], objectSrc: ["'none'"], baseUri: ["'self'"], frameAncestors: ["'none'"] } }));"#.into(),
            cloudflare: r#"Rules -> Transform Rules -> Modify Response Header -> Set static: Content-Security-Policy = default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"#.into(),
        },
        "click" => RemediationSnippet {
            title: "Clickjacking Protection (frame-ancestors / X-Frame-Options)".into(),
            nginx: "add_header X-Frame-Options \"DENY\" always;\nadd_header Content-Security-Policy \"frame-ancestors 'none'\" always;".into(),
            apache: "Header always set X-Frame-Options \"DENY\"\nHeader always append Content-Security-Policy \"frame-ancestors 'none'\"".into(),
            express: r#"app.use(helmet.frameguard({ action: "deny" }));"#.into(),
            cloudflare: r#"Rules -> Transform Rules -> Modify Response Header -> Set static: X-Frame-Options = DENY"#.into(),
        },
        "xcto" => RemediationSnippet {
            title: "X-Content-Type-Options".into(),
            nginx: r#"add_header X-Content-Type-Options "nosniff" always;"#.into(),
            apache: r#"Header always set X-Content-Type-Options "nosniff""#.into(),
            express: r#"app.use(helmet.noSniff());"#.into(),
            cloudflare: r#"Rules -> Transform Rules -> Modify Response Header -> Set static: X-Content-Type-Options = nosniff"#.into(),
        },
        "referrerPolicy" => RemediationSnippet {
            title: "Referrer-Policy".into(),
            nginx: r#"add_header Referrer-Policy "strict-origin-when-cross-origin" always;"#.into(),
            apache: r#"Header always set Referrer-Policy "strict-origin-when-cross-origin""#.into(),
            express: r#"app.use(helmet.referrerPolicy({ policy: "strict-origin-when-cross-origin" }));"#.into(),
            cloudflare: r#"Rules -> Transform Rules -> Modify Response Header -> Set static: Referrer-Policy = strict-origin-when-cross-origin"#.into(),
        },
        "perm" => RemediationSnippet {
            title: "Permissions-Policy".into(),
            nginx: r#"add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;"#.into(),
            apache: r#"Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()""#.into(),
            express: r#"res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");"#.into(),
            cloudflare: r#"Rules -> Transform Rules -> Modify Response Header -> Set static: Permissions-Policy = camera=(), microphone=(), geolocation=()"#.into(),
        },
        "coop" => RemediationSnippet {
            title: "Cross-Origin-Opener-Policy (COOP)".into(),
            nginx: r#"add_header Cross-Origin-Opener-Policy "same-origin" always;"#.into(),
            apache: r#"Header always set Cross-Origin-Opener-Policy "same-origin""#.into(),
            express: r#"app.use(helmet.crossOriginOpenerPolicy({ policy: "same-origin" }));"#.into(),
            cloudflare: r#"Rules -> Transform Rules -> Modify Response Header -> Set static: Cross-Origin-Opener-Policy = same-origin"#.into(),
        },
        "coep" => RemediationSnippet {
            title: "Cross-Origin-Embedder-Policy (COEP)".into(),
            nginx: r#"add_header Cross-Origin-Embedder-Policy "require-corp" always;"#.into(),
            apache: r#"Header always set Cross-Origin-Embedder-Policy "require-corp""#.into(),
            express: r#"app.use(helmet.crossOriginEmbedderPolicy({ policy: "require-corp" }));"#.into(),
            cloudflare: r#"Rules -> Transform Rules -> Modify Response Header -> Set static: Cross-Origin-Embedder-Policy = require-corp"#.into(),
        },
        "corp" => RemediationSnippet {
            title: "Cross-Origin-Resource-Policy (CORP)".into(),
            nginx: r#"add_header Cross-Origin-Resource-Policy "same-origin" always;"#.into(),
            apache: r#"Header always set Cross-Origin-Resource-Policy "same-origin""#.into(),
            express: r#"app.use(helmet.crossOriginResourcePolicy({ policy: "same-origin" }));"#.into(),
            cloudflare: r#"Rules -> Transform Rules -> Modify Response Header -> Set static: Cross-Origin-Resource-Policy = same-origin"#.into(),
        },
        "acao" => RemediationSnippet {
            title: "CORS (Access-Control-Allow-Origin)".into(),
            nginx: r#"add_header Access-Control-Allow-Origin "https://app.example.com" always;"#.into(),
            apache: r#"Header always set Access-Control-Allow-Origin "https://app.example.com""#.into(),
            express: r#"app.use(cors({ origin: ["https://app.example.com"], credentials: true }));"#.into(),
            cloudflare: r#"Restrict CORS origin in Workers or Transform Rules to explicit trusted domains (avoid '*')."#.into(),
        },
        "cookies" => RemediationSnippet {
            title: "Set-Cookie Flags (Secure, HttpOnly, SameSite)".into(),
            nginx: r#"proxy_cookie_flags ~ secure httponly samesite=lax;"#.into(),
            apache: r#"Header edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax""#.into(),
            express: r#"res.cookie("session", token, { secure: true, httpOnly: true, sameSite: "lax" });"#.into(),
            cloudflare: r#"Set Secure, HttpOnly, and SameSite=Lax/Strict attributes on origin or via Cloudflare Worker."#.into(),
        },
        "server" => RemediationSnippet {
            title: "Hide Server Banner".into(),
            nginx: "server_tokens off;\n# With headers-more module: more_clear_headers Server;".into(),
            apache: "ServerTokens Prod\nServerSignature Off".into(),
            express: r#"res.removeHeader("Server");"#.into(),
            cloudflare: r#"Rules -> Transform Rules -> Modify Response Header -> Remove: Server (Enterprise) or strip at origin."#.into(),
        },
        "xpb" | "infoLeak" => RemediationSnippet {
            title: "Hide Technology Disclosure Headers".into(),
            nginx: "proxy_hide_header X-Powered-By;\nproxy_hide_header X-AspNet-Version;\nproxy_hide_header X-AspNetMvc-Version;".into(),
            apache: "Header always unset X-Powered-By\nHeader always unset X-AspNet-Version".into(),
            express: r#"app.disable("x-powered-by");"#.into(),
            cloudflare: r#"Rules -> Transform Rules -> Modify Response Header -> Remove: X-Powered-By"#.into(),
        },
        "xxss" => RemediationSnippet {
            title: "X-XSS-Protection".into(),
            nginx: r#"add_header X-XSS-Protection "0" always;"#.into(),
            apache: r#"Header always set X-XSS-Protection "0""#.into(),
            express: r#"app.use(helmet.xssFilter()); // sets 0 in Helmet v4+"#.into(),
            cloudflare: r#"Rules -> Transform Rules -> Modify Response Header -> Set static: X-XSS-Protection = 0"#.into(),
        },
        _ => return None,
    };
    Some(snippet)
}
