pub mod analyzers;
pub mod config;
pub mod fetcher;
pub mod model;
pub mod remediation;
pub mod scorer;
pub mod snapshot;
pub mod ssrf;

pub use config::ScanConfig;
pub use fetcher::Scanner;
pub use model::{
    CheckStatus, CheckSummary, DiffTrend, DomainDiff, Grade, HeaderCheck, HeaderDiff, RedirectHop,
    RemediationSnippet, ScanDiff, ScanResult, ScanSnapshot,
};
pub use snapshot::{compute_diff, from_yaml, load_snapshot, save_snapshot, to_yaml};
