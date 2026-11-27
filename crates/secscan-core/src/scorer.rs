use crate::model::{CheckStatus, Grade, HeaderCheck};
use std::collections::BTreeMap;

/// Computes a weighted security score (0..=100) and letter grade (A+..=F) from header checks.
pub fn compute_score(checks: &BTreeMap<String, HeaderCheck>) -> (u8, Grade) {
    let weights: &[(&str, f32)] = &[
        ("hsts", 18.0),
        ("csp", 22.0),
        ("click", 12.0),
        ("xcto", 10.0),
        ("referrerPolicy", 8.0),
        ("perm", 6.0),
        ("cookies", 8.0),
        ("coop", 4.0),
        ("coep", 2.0),
        ("corp", 4.0),
        ("server", 2.0),
        ("xpb", 2.0),
        ("infoLeak", 2.0),
    ];

    let mut total_weight = 0.0_f32;
    let mut earned = 0.0_f32;

    for (key, weight) in weights {
        if let Some(check) = checks.get(*key) {
            // Neutral `Info` (e.g., no cookies set or optional COEP) does not penalize the site.
            if check.status == CheckStatus::Info {
                continue;
            }
            total_weight += *weight;
            earned += match check.status {
                CheckStatus::Pass => *weight,
                CheckStatus::Warn => *weight * 0.5,
                CheckStatus::Fail => 0.0,
                CheckStatus::Info => *weight,
            };
        }
    }

    // Extra penalties for misconfigured CORS wildcard or invalid/deprecated X-XSS-Protection
    let mut penalty = 0.0_f32;
    if let Some(acao) = checks.get("acao") {
        match acao.status {
            CheckStatus::Fail => penalty += 10.0,
            CheckStatus::Warn => penalty += 4.0,
            _ => {}
        }
    }
    if let Some(xxss) = checks.get("xxss") {
        match xxss.status {
            CheckStatus::Fail => penalty += 4.0,
            CheckStatus::Warn => penalty += 2.0,
            _ => {}
        }
    }

    let raw = if total_weight > 0.0 {
        (earned / total_weight) * 100.0 - penalty
    } else {
        0.0
    };
    let score = raw.round().clamp(0.0, 100.0) as u8;

    let critical_fail = ["hsts", "csp", "click", "xcto"].iter().any(|k| {
        checks
            .get(*k)
            .map(|c| c.status == CheckStatus::Fail)
            .unwrap_or(false)
    });

    let grade = if score >= 95 && !critical_fail {
        Grade::APlus
    } else if score >= 85 && !critical_fail {
        Grade::A
    } else if score >= 70 {
        Grade::B
    } else if score >= 55 {
        Grade::C
    } else if score >= 40 {
        Grade::D
    } else {
        Grade::F
    };

    (score, grade)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::analyze_all;
    use http::{HeaderMap, HeaderValue};

    #[test]
    fn perfect_headers_score_100_a_plus() {
        let mut h = HeaderMap::new();
        h.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
        );
        h.insert(
            "content-security-policy",
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            ),
        );
        h.insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
        h.insert(
            "referrer-policy",
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        );
        h.insert(
            "permissions-policy",
            HeaderValue::from_static("camera=(), microphone=()"),
        );
        h.insert(
            "cross-origin-opener-policy",
            HeaderValue::from_static("same-origin"),
        );
        h.insert(
            "cross-origin-resource-policy",
            HeaderValue::from_static("same-origin"),
        );

        let (checks, _) = analyze_all(&h, "https://secure.example/");
        let (score, grade) = compute_score(&checks);
        assert_eq!(score, 100);
        assert_eq!(grade, Grade::APlus);
    }

    #[test]
    fn empty_http_headers_score_low_grade_f() {
        let h = HeaderMap::new();
        let (checks, _) = analyze_all(&h, "http://insecure.example/");
        let (score, grade) = compute_score(&checks);
        assert!(score < 20, "Expected low score, got {score}");
        assert_eq!(grade, Grade::F);
    }
}
