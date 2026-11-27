use crate::model::{CheckStatus, DiffTrend, DomainDiff, HeaderDiff, ScanDiff, ScanSnapshot};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("I/O error accessing YAML snapshot: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to serialize/deserialize YAML snapshot: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

/// Loads a previously saved YAML snapshot if the file exists.
pub fn load_snapshot(path: &Path) -> Result<Option<ScanSnapshot>, SnapshotError> {
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(path)?;
    if content.trim().is_empty() {
        return Ok(None);
    }
    let snapshot: ScanSnapshot = serde_yaml::from_str(&content)?;
    Ok(Some(snapshot))
}

/// Atomically writes a scan snapshot to `path` in YAML format.
pub fn save_snapshot(path: &Path, snapshot: &ScanSnapshot) -> Result<(), SnapshotError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let yaml = serde_yaml::to_string(snapshot)?;
    let tmp_path = path.with_extension("yaml.tmp");
    fs::write(&tmp_path, yaml)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

pub fn to_yaml(snapshot: &ScanSnapshot) -> Result<String, SnapshotError> {
    Ok(serde_yaml::to_string(snapshot)?)
}

pub fn from_yaml(yaml: &str) -> Result<ScanSnapshot, SnapshotError> {
    Ok(serde_yaml::from_str(yaml)?)
}

fn status_rank(status: CheckStatus) -> i8 {
    match status {
        CheckStatus::Fail => 0,
        CheckStatus::Warn => 1,
        CheckStatus::Info => 2,
        CheckStatus::Pass => 3,
    }
}

/// Computes a structured diff between a `previous` snapshot and a `current` snapshot.
pub fn compute_diff(previous: &ScanSnapshot, current: &ScanSnapshot) -> ScanDiff {
    let prev_map: BTreeMap<&str, _> = previous
        .results
        .iter()
        .map(|r| (r.domain.as_str(), r))
        .collect();
    let curr_map: BTreeMap<&str, _> = current
        .results
        .iter()
        .map(|r| (r.domain.as_str(), r))
        .collect();

    let all_domains: BTreeSet<&str> = prev_map.keys().chain(curr_map.keys()).copied().collect();

    let mut improved = 0;
    let mut regressed = 0;
    let mut unchanged = 0;
    let mut added = 0;
    let mut removed = 0;
    let mut domains = BTreeMap::new();

    for domain in all_domains {
        match (prev_map.get(domain), curr_map.get(domain)) {
            (None, Some(curr)) => {
                added += 1;
                domains.insert(
                    domain.to_string(),
                    DomainDiff {
                        domain: domain.to_string(),
                        trend: DiffTrend::New,
                        previous_score: None,
                        current_score: curr.score,
                        score_delta: None,
                        previous_grade: None,
                        current_grade: curr.grade,
                        header_changes: Vec::new(),
                    },
                );
            }
            (Some(prev), None) => {
                removed += 1;
                domains.insert(
                    domain.to_string(),
                    DomainDiff {
                        domain: domain.to_string(),
                        trend: DiffTrend::Removed,
                        previous_score: prev.score,
                        current_score: None,
                        score_delta: None,
                        previous_grade: prev.grade,
                        current_grade: None,
                        header_changes: Vec::new(),
                    },
                );
            }
            (Some(prev), Some(curr)) => {
                let mut header_changes = Vec::new();
                for (key, curr_check) in &curr.checks {
                    if let Some(prev_check) = prev.checks.get(key) {
                        if prev_check.status != curr_check.status {
                            let trend = if status_rank(curr_check.status)
                                > status_rank(prev_check.status)
                            {
                                DiffTrend::Improved
                            } else {
                                DiffTrend::Regressed
                            };
                            header_changes.push(HeaderDiff {
                                key: key.clone(),
                                header: curr_check.header.clone(),
                                before: prev_check.status,
                                after: curr_check.status,
                                trend,
                            });
                        }
                    }
                }

                let score_delta = match (prev.score, curr.score) {
                    (Some(p), Some(c)) => Some(c as i16 - p as i16),
                    _ => None,
                };

                let trend = match score_delta {
                    Some(d) if d > 0 => DiffTrend::Improved,
                    Some(d) if d < 0 => DiffTrend::Regressed,
                    _ => {
                        let imp = header_changes
                            .iter()
                            .filter(|h| h.trend == DiffTrend::Improved)
                            .count();
                        let reg = header_changes
                            .iter()
                            .filter(|h| h.trend == DiffTrend::Regressed)
                            .count();
                        if imp > reg {
                            DiffTrend::Improved
                        } else if reg > imp {
                            DiffTrend::Regressed
                        } else {
                            DiffTrend::Unchanged
                        }
                    }
                };

                match trend {
                    DiffTrend::Improved => improved += 1,
                    DiffTrend::Regressed => regressed += 1,
                    _ => unchanged += 1,
                }

                domains.insert(
                    domain.to_string(),
                    DomainDiff {
                        domain: domain.to_string(),
                        trend,
                        previous_score: prev.score,
                        current_score: curr.score,
                        score_delta,
                        previous_grade: prev.grade,
                        current_grade: curr.grade,
                        header_changes,
                    },
                );
            }
            (None, None) => {}
        }
    }

    ScanDiff {
        previous_timestamp: previous.timestamp,
        current_timestamp: current.timestamp,
        improved,
        regressed,
        unchanged,
        added,
        removed,
        domains,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::analyze_all;
    use crate::model::ScanResult;
    use crate::scorer::compute_score;
    use http::{HeaderMap, HeaderValue};

    fn make_result(domain: &str, headers: &HeaderMap) -> ScanResult {
        let final_url = format!("https://{domain}/");
        let (checks, summary) = analyze_all(headers, &final_url);
        let (score, grade) = compute_score(&checks);
        ScanResult {
            domain: domain.into(),
            ok: true,
            error: None,
            error_code: None,
            status: Some(200),
            final_url: Some(final_url),
            https_enforced: true,
            http_redirected_to_https: true,
            redirect_chain: vec![],
            duration_ms: 42,
            score: Some(score),
            grade: Some(grade),
            summary,
            checks,
            raw_headers: BTreeMap::new(),
            remediations: BTreeMap::new(),
        }
    }

    #[test]
    fn saves_loads_and_computes_yaml_diff() {
        let mut h1 = HeaderMap::new();
        h1.insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );

        let mut h2 = h1.clone();
        h2.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        );

        let prev = ScanSnapshot::from_results(vec![
            make_result("example.com", &h1),
            make_result("removed.example", &h1),
        ]);
        let curr = ScanSnapshot::from_results(vec![
            make_result("example.com", &h2),
            make_result("new.example", &h2),
        ]);

        let tmp = std::env::temp_dir().join(format!(
            "secscan-test-{}.yaml",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        save_snapshot(&tmp, &prev).unwrap();
        let loaded = load_snapshot(&tmp).unwrap().unwrap();
        let _ = fs::remove_file(&tmp);

        let diff = compute_diff(&loaded, &curr);
        assert_eq!(diff.improved, 1);
        assert_eq!(diff.added, 1);
        assert_eq!(diff.removed, 1);
        assert_eq!(diff.domains["example.com"].trend, DiffTrend::Improved);
        assert!(diff.domains["example.com"].score_delta.unwrap() > 0);
        assert!(diff.domains["example.com"]
            .header_changes
            .iter()
            .any(|c| c.key == "hsts" && c.trend == DiffTrend::Improved));
    }
}
