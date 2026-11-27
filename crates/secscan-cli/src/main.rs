use clap::{Parser, ValueEnum};
use secscan_core::{
    compute_diff, load_snapshot, save_snapshot, to_yaml, CheckStatus, DiffTrend, Grade, ScanConfig,
    ScanDiff, ScanSnapshot, Scanner,
};
use serde_json::json;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
    Yaml,
    Sarif,
}

#[derive(Debug, Parser)]
#[command(
    name = "secscan",
    version,
    about = "Fast Rust HTTP security headers scanner with SSRF protection, scoring, and YAML diff"
)]
struct Args {
    /// Domains or URLs to scan
    domains: Vec<String>,

    /// Read newline-separated domains from a text file (# lines are ignored)
    #[arg(short = 'f', long)]
    file: Option<PathBuf>,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    format: OutputFormat,

    /// Maximum concurrent domain scans
    #[arg(short = 'c', long, default_value_t = 15)]
    concurrency: usize,

    /// Allow scanning private/loopback/internal IP ranges (disabled by default for SSRF safety)
    #[arg(long, env = "ALLOW_PRIVATE_NETWORKS", default_value_t = false)]
    allow_private: bool,

    /// Allow self-signed TLS certificates (use only in trusted staging/internal networks)
    #[arg(long, env = "ALLOW_SELF_SIGNED_TLS", default_value_t = false)]
    allow_self_signed: bool,

    /// Minimum required security grade (A+, A, B, C, D, F); exits with code 2 if any target fails
    #[arg(long)]
    min_grade: Option<Grade>,

    /// Previous YAML snapshot file to compute diff against
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Save current scan snapshot to a YAML file
    #[arg(long)]
    save_yaml: Option<PathBuf>,

    /// Write formatted report to a file instead of stdout
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    let mut targets = Vec::new();
    let mut seen = HashSet::new();

    for d in &args.domains {
        let trimmed = d.trim();
        if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
            targets.push(trimmed.to_string());
        }
    }

    if let Some(ref file_path) = args.file {
        match fs::read_to_string(file_path) {
            Ok(content) => {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    if seen.insert(trimmed.to_string()) {
                        targets.push(trimmed.to_string());
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading {}: {e}", file_path.display());
                return ExitCode::from(1);
            }
        }
    }

    if targets.is_empty() {
        eprintln!("No targets provided. Pass domains as arguments or via --file <path>.");
        return ExitCode::from(1);
    }

    let config = ScanConfig {
        concurrency: args.concurrency.clamp(1, 100),
        allow_private_networks: args.allow_private,
        allow_self_signed_tls: args.allow_self_signed,
        ..Default::default()
    };

    let scanner = match Scanner::new(config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to initialize HTTP scanner: {e}");
            return ExitCode::from(1);
        }
    };

    let previous = if let Some(ref baseline_path) = args.baseline {
        match load_snapshot(baseline_path) {
            Ok(snap) => snap,
            Err(e) => {
                eprintln!(
                    "Failed to load baseline YAML {}: {e}",
                    baseline_path.display()
                );
                return ExitCode::from(1);
            }
        }
    } else {
        None
    };

    let results = scanner.scan_many(targets).await;
    let snapshot = ScanSnapshot::from_results(results);
    let diff = previous.as_ref().map(|prev| compute_diff(prev, &snapshot));

    if let Some(ref save_path) = args.save_yaml {
        if let Err(e) = save_snapshot(save_path, &snapshot) {
            eprintln!(
                "Failed to save YAML snapshot to {}: {e}",
                save_path.display()
            );
            return ExitCode::from(1);
        }
    }

    let rendered = match args.format {
        OutputFormat::Table => render_table(&snapshot, diff.as_ref()),
        OutputFormat::Json => {
            serde_json::to_string_pretty(&json!({ "snapshot": snapshot, "diff": diff }))
                .unwrap_or_default()
        }
        OutputFormat::Yaml => match to_yaml(&snapshot) {
            Ok(y) => y,
            Err(e) => {
                eprintln!("Failed to render YAML: {e}");
                return ExitCode::from(1);
            }
        },
        OutputFormat::Sarif => render_sarif(&snapshot),
    };

    if let Some(ref out_path) = args.output {
        if let Err(e) = fs::write(out_path, rendered) {
            eprintln!("Failed to write {}: {e}", out_path.display());
            return ExitCode::from(1);
        }
    } else {
        println!("{rendered}");
    }

    if let Some(min_grade) = args.min_grade {
        let violated = snapshot
            .results
            .iter()
            .any(|r| !r.ok || r.grade.map(|g| g < min_grade).unwrap_or(true));
        if violated {
            eprintln!("Grade gate failed: one or more targets scored below {min_grade}.");
            return ExitCode::from(2);
        }
    }

    ExitCode::SUCCESS
}

fn render_table(snapshot: &ScanSnapshot, diff: Option<&ScanDiff>) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{:<34} {:<6} {:<6} {:<6} {:<16} {}\n",
        "DOMAIN", "HTTP", "SCORE", "GRADE", "P/W/F/I", "DIFF / STATUS"
    ));
    out.push_str(&"-".repeat(92));
    out.push('\n');

    for r in &snapshot.results {
        let http = r
            .status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "ERR".to_string());
        let score = r
            .score
            .map(|s| format!("{s}/100"))
            .unwrap_or_else(|| "-".to_string());
        let grade = r
            .grade
            .map(|g| g.to_string())
            .unwrap_or_else(|| "-".to_string());
        let pwfi = format!(
            "{}/{}/{}/{}",
            r.summary.pass, r.summary.warn, r.summary.fail, r.summary.info
        );

        let note = if !r.ok {
            r.error.clone().unwrap_or_else(|| "Error".to_string())
        } else if let Some(d) = diff.and_then(|df| df.domains.get(&r.domain)) {
            match d.trend {
                DiffTrend::Improved => {
                    format!("IMPROVED ({:+})", d.score_delta.unwrap_or(0))
                }
                DiffTrend::Regressed => {
                    format!("REGRESSED ({:+})", d.score_delta.unwrap_or(0))
                }
                DiffTrend::New => "NEW".to_string(),
                DiffTrend::Unchanged => "UNCHANGED".to_string(),
                DiffTrend::Removed => "REMOVED".to_string(),
            }
        } else {
            r.final_url.clone().unwrap_or_default()
        };

        out.push_str(&format!(
            "{:<34} {:<6} {:<6} {:<6} {:<16} {}\n",
            truncate(&r.domain, 33),
            http,
            score,
            grade,
            pwfi,
            note
        ));
    }

    if let Some(d) = diff {
        out.push_str(&format!(
            "\nDiff vs {}: +{} improved, -{} regressed, ={} unchanged, {} new, {} removed",
            d.previous_timestamp.to_rfc3339(),
            d.improved,
            d.regressed,
            d.unchanged,
            d.added,
            d.removed
        ));
    }

    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut cut: String = s.chars().take(max.saturating_sub(1)).collect();
        cut.push('…');
        cut
    }
}

fn render_sarif(snapshot: &ScanSnapshot) -> String {
    let mut results = Vec::new();
    for r in &snapshot.results {
        if !r.ok {
            results.push(json!({
                "ruleId": r.error_code.as_deref().unwrap_or("scan.error"),
                "level": "error",
                "message": { "text": format!("{}: {}", r.domain, r.error.as_deref().unwrap_or("scan failed")) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": r.domain }
                    }
                }]
            }));
            continue;
        }

        for check in r.checks.values() {
            let level = match check.status {
                CheckStatus::Fail => "error",
                CheckStatus::Warn => "warning",
                CheckStatus::Pass | CheckStatus::Info => continue,
            };
            results.push(json!({
                "ruleId": check.code,
                "level": level,
                "message": { "text": format!("[{}] {}: {}", r.domain, check.header, check.reason) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": r.final_url.as_deref().unwrap_or(&r.domain) }
                    }
                }]
            }));
        }
    }

    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "secscan",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/MuhammedSafa/Security-Headers-Scanner"
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}
