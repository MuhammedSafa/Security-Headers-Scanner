use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Grade {
    F = 0,
    D = 1,
    C = 2,
    B = 3,
    A = 4,
    #[serde(rename = "A+")]
    APlus = 5,
}

impl fmt::Display for Grade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Grade::APlus => write!(f, "A+"),
            Grade::A => write!(f, "A"),
            Grade::B => write!(f, "B"),
            Grade::C => write!(f, "C"),
            Grade::D => write!(f, "D"),
            Grade::F => write!(f, "F"),
        }
    }
}

impl FromStr for Grade {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_uppercase().as_str() {
            "A+" => Ok(Grade::APlus),
            "A" => Ok(Grade::A),
            "B" => Ok(Grade::B),
            "C" => Ok(Grade::C),
            "D" => Ok(Grade::D),
            "F" => Ok(Grade::F),
            other => Err(format!(
                "Invalid grade '{other}'. Expected one of: A+, A, B, C, D, F"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectHop {
    pub url: String,
    pub status: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderCheck {
    pub key: String,
    pub header: String,
    pub status: CheckStatus,
    pub code: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
    pub value: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationSnippet {
    pub title: String,
    pub nginx: String,
    pub apache: String,
    pub express: String,
    pub cloudflare: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckSummary {
    pub pass: usize,
    pub warn: usize,
    pub fail: usize,
    pub info: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    pub domain: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,
    #[serde(default)]
    pub https_enforced: bool,
    #[serde(default)]
    pub http_redirected_to_https: bool,
    #[serde(default)]
    pub redirect_chain: Vec<RedirectHop>,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grade: Option<Grade>,
    #[serde(default)]
    pub summary: CheckSummary,
    #[serde(default)]
    pub checks: BTreeMap<String, HeaderCheck>,
    #[serde(default)]
    pub raw_headers: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub remediations: BTreeMap<String, RemediationSnippet>,
}

impl ScanResult {
    pub fn failure(
        domain: impl Into<String>,
        error_code: impl Into<String>,
        error: impl Into<String>,
        duration_ms: u64,
    ) -> Self {
        Self {
            domain: domain.into(),
            ok: false,
            error: Some(error.into()),
            error_code: Some(error_code.into()),
            status: None,
            final_url: None,
            https_enforced: false,
            http_redirected_to_https: false,
            redirect_chain: Vec::new(),
            duration_ms,
            score: None,
            grade: None,
            summary: CheckSummary::default(),
            checks: BTreeMap::new(),
            raw_headers: BTreeMap::new(),
            remediations: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSnapshot {
    pub version: u32,
    pub timestamp: DateTime<Utc>,
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub average_score: Option<f32>,
    pub results: Vec<ScanResult>,
}

impl ScanSnapshot {
    pub fn from_results(results: Vec<ScanResult>) -> Self {
        let total = results.len();
        let succeeded = results.iter().filter(|r| r.ok).count();
        let failed = total - succeeded;
        let scores: Vec<f32> = results
            .iter()
            .filter_map(|r| r.score.map(f32::from))
            .collect();
        let average_score = if scores.is_empty() {
            None
        } else {
            let avg = scores.iter().sum::<f32>() / scores.len() as f32;
            Some((avg * 10.0).round() / 10.0)
        };

        Self {
            version: 1,
            timestamp: Utc::now(),
            total,
            succeeded,
            failed,
            average_score,
            results,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiffTrend {
    Improved,
    Regressed,
    Unchanged,
    New,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderDiff {
    pub key: String,
    pub header: String,
    pub before: CheckStatus,
    pub after: CheckStatus,
    pub trend: DiffTrend,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainDiff {
    pub domain: String,
    pub trend: DiffTrend,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_score: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_score: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score_delta: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_grade: Option<Grade>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_grade: Option<Grade>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub header_changes: Vec<HeaderDiff>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanDiff {
    pub previous_timestamp: DateTime<Utc>,
    pub current_timestamp: DateTime<Utc>,
    pub improved: usize,
    pub regressed: usize,
    pub unchanged: usize,
    pub added: usize,
    pub removed: usize,
    pub domains: BTreeMap<String, DomainDiff>,
}
