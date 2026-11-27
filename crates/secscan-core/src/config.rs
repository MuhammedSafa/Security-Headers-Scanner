use std::env;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub concurrency: usize,
    pub max_domains_per_request: usize,
    pub hop_timeout: Duration,
    pub global_timeout: Duration,
    pub max_redirects: usize,
    pub retries: usize,
    pub allow_private_networks: bool,
    pub allow_self_signed_tls: bool,
    pub user_agent: String,
    pub last_scan_path: PathBuf,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            concurrency: 15,
            max_domains_per_request: 500,
            hop_timeout: Duration::from_millis(7_000),
            global_timeout: Duration::from_millis(20_000),
            max_redirects: 5,
            retries: 1,
            allow_private_networks: false,
            allow_self_signed_tls: false,
            user_agent:
                "SecHeadersScanner/2.0 (+https://github.com/MuhammedSafa/Security-Headers-Scanner)"
                    .to_string(),
            last_scan_path: PathBuf::from("./data/last-scan.yaml"),
        }
    }
}

impl ScanConfig {
    pub fn from_env() -> Self {
        let defaults = Self::default();

        let concurrency = env_usize("SCAN_CONCURRENCY", defaults.concurrency).clamp(1, 100);
        let max_domains_per_request =
            env_usize("MAX_DOMAINS_PER_REQUEST", defaults.max_domains_per_request).clamp(1, 5_000);
        let hop_timeout_ms =
            env_u64("HOP_TIMEOUT_MS", defaults.hop_timeout.as_millis() as u64).clamp(1_000, 60_000);
        let global_timeout_ms = env_u64(
            "GLOBAL_TIMEOUT_MS",
            defaults.global_timeout.as_millis() as u64,
        )
        .clamp(2_000, 120_000);
        let max_redirects = env_usize("MAX_REDIRECTS", defaults.max_redirects).clamp(0, 15);
        let allow_private_networks =
            env_bool("ALLOW_PRIVATE_NETWORKS", defaults.allow_private_networks);
        let allow_self_signed_tls =
            env_bool("ALLOW_SELF_SIGNED_TLS", defaults.allow_self_signed_tls);
        let last_scan_path = env::var("LAST_SCAN_PATH")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or(defaults.last_scan_path);

        Self {
            concurrency,
            max_domains_per_request,
            hop_timeout: Duration::from_millis(hop_timeout_ms),
            global_timeout: Duration::from_millis(global_timeout_ms),
            max_redirects,
            retries: defaults.retries,
            allow_private_networks,
            allow_self_signed_tls,
            user_agent: defaults.user_agent,
            last_scan_path,
        }
    }
}

fn env_usize(key: &str, default: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key).ok().as_deref().map(str::trim) {
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES") => true,
        Some("0") | Some("false") | Some("FALSE") | Some("no") | Some("NO") => false,
        _ => default,
    }
}
