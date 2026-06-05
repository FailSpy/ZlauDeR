//! Detection: presidio analyzer + custom rules, filtered and overlap-resolved
//! into a sorted, non-overlapping span list with a resolved operator each.

use presidio_analyzer::{AnalyzeRequest, AnalyzerEngine};
use presidio_core::{Recognizer, RecognizerResult};
use regex::{Regex, RegexBuilder};
use std::collections::HashSet;

use crate::cache::{CachedDetection, Source};
use crate::config::{CustomReplacement, EngineConfig, Operator};
use crate::error::EngineError;
use crate::surface::Surface;

/// Identity of the bundled (compiled-in) regex/custom recognizer set. Folded into
/// `policy_fp` (audit #1) so a change to the detection code abandons stale cache
/// entries — both the in-memory cache (belt-and-suspenders: a new binary already
/// starts with an empty cache) and any future on-disk backend. BUMP THIS whenever
/// the presidio recognizer set or this module's detection logic changes in a way
/// that alters output for unchanged input.
pub const DETECTOR_VERSION: u64 = 1;

/// A custom rule compiled to a regex (literal rules are escaped). Matching via
/// regex on the original text gives correct byte offsets for any case folding.
#[derive(Clone)]
pub struct CompiledCustom {
    re: Regex,
    pub entity_type: String,
    pub literal_token: bool,
    pub token: Option<String>,
    pub priority: u32,
    pub surfaces: Option<HashSet<Surface>>,
}

pub fn compile_customs(rules: &[CustomReplacement]) -> Result<Vec<CompiledCustom>, EngineError> {
    let mut out = Vec::with_capacity(rules.len());
    for r in rules {
        let raw = if r.is_regex {
            r.pattern.clone()
        } else {
            regex::escape(&r.pattern)
        };
        let re = RegexBuilder::new(&raw)
            .case_insensitive(!r.case_sensitive)
            .build()
            .map_err(|source| EngineError::BadCustomRegex {
                pattern: r.pattern.clone(),
                source,
            })?;
        out.push(CompiledCustom {
            re,
            entity_type: r.entity_type.clone(),
            literal_token: r.literal_token,
            token: r.token.clone(),
            priority: r.priority,
            surfaces: r.apply_to_surfaces.clone(),
        });
    }
    // Lower `priority` value = higher precedence; apply those first.
    out.sort_by_key(|c| c.priority);
    Ok(out)
}

/// Resolve the apply-time operator for a (cached) detection from the LIVE policy
/// config (audit #4): operators are NOT cached, so a per-type override / default
/// change applies on the next mask with no detection re-run. A `literal_token`
/// custom is always `Token` (a structural property of the rule, captured in
/// `det.literal`); everything else follows `operator_for`.
pub fn resolve_operator(cfg: &EngineConfig, det: &CachedDetection) -> Operator {
    if det.literal {
        Operator::Token
    } else {
        cfg.operator_for(&det.entity_type)
    }
}

pub fn run_detection(
    analyzer: &AnalyzerEngine,
    cfg: &EngineConfig,
    customs: &[CompiledCustom],
    ml: Option<&dyn Recognizer>,
    text: &str,
    surface: Surface,
) -> Result<Vec<CachedDetection>, EngineError> {
    let mut dets: Vec<CachedDetection> = Vec::new();
    // Spans of allow-listed values; any detection fully contained in one of these
    // is also suppressed (allow-listing "admin@example.com" covers its
    // "example.com" sub-domain too).
    let mut allowed_spans: Vec<(usize, usize)> = Vec::new();

    // Pass 1: custom rules (already priority-sorted).
    for c in customs {
        if let Some(surfs) = &c.surfaces
            && !surfs.contains(&surface)
        {
            continue;
        }
        for m in c.re.find_iter(text) {
            let slice = &text[m.start()..m.end()];
            if cfg.allow_list.is_allowed(slice) {
                allowed_spans.push((m.start(), m.end()));
                continue;
            }
            // Operator is resolved at APPLY time (see `resolve_operator`); we record
            // only the structural `literal` marker + the fixed token here.
            dets.push(CachedDetection {
                start: m.start(),
                end: m.end(),
                entity_type: c.entity_type.clone(),
                score: 1.0,
                source: Source::Custom,
                literal: c.literal_token,
                fixed_token: if c.literal_token {
                    c.token.clone()
                } else {
                    None
                },
            });
        }
    }

    // Pass 2: presidio regex analyzer.
    let results = analyzer
        .analyze(AnalyzeRequest::new(text, &cfg.language).score_threshold(cfg.score_threshold));
    ingest_results(results, cfg, text, &mut dets, &mut allowed_spans, Source::Regex);

    // Pass 2b: the optional ML recognizer (openai/privacy-filter), if loaded. It
    // returns the same `RecognizerResult` type, so it flows through the identical
    // category gate / allow-list / overlap dedup below — e.g. its PERSON/LOCATION
    // spans only mask when the `personal` category is on. Tagged `Source::Ml` so the
    // deferred Component-3 burn can single it out.
    if let Some(rec) = ml {
        let ml_results = rec.analyze(text, None, None);
        ingest_results(ml_results, cfg, text, &mut dets, &mut allowed_spans, Source::Ml);
    }

    // Suppress detections fully contained within an allow-listed span.
    if !allowed_spans.is_empty() {
        dets.retain(|d| {
            !allowed_spans
                .iter()
                .any(|(s, e)| *s <= d.start && d.end <= *e)
        });
    }

    Ok(resolve_overlaps(dets))
}

/// Filter one recognizer's results through the engine policy and push survivors to
/// `dets` (allow-listed values are recorded as suppression spans instead). Shared
/// by the regex analyzer (Pass 2) and the ML recognizer (Pass 2b) so both get
/// identical category-gate / allow-list / operator treatment.
fn ingest_results(
    results: Vec<RecognizerResult>,
    cfg: &EngineConfig,
    text: &str,
    dets: &mut Vec<CachedDetection>,
    allowed_spans: &mut Vec<(usize, usize)>,
    source: Source,
) {
    for r in results {
        // One predictable score floor across both sources. The regex analyzer is
        // already filtered to this threshold; the ML recognizer applies its own
        // `min_score`, so re-applying here keeps the engine-wide floor authoritative.
        if r.score < cfg.score_threshold {
            continue;
        }
        let entity_type = r.entity_type.to_string();
        if !cfg.entity_enabled(&entity_type) {
            continue;
        }
        let Some(slice) = r.text(text) else {
            continue;
        };
        if slice.is_empty() {
            continue;
        }
        if cfg.allow_list.is_allowed(slice) {
            allowed_spans.push((r.start, r.end));
            continue;
        }
        dets.push(CachedDetection {
            start: r.start,
            end: r.end,
            entity_type,
            score: r.score,
            source,
            literal: false,
            fixed_token: None,
        });
    }
}

/// Keep the best detection on overlap: custom > presidio/ml, then higher score,
/// then longer span. Returns the survivors sorted by `start`.
fn resolve_overlaps(mut dets: Vec<CachedDetection>) -> Vec<CachedDetection> {
    // Best first.
    dets.sort_by(|a, b| {
        let a_custom = a.source == Source::Custom;
        let b_custom = b.source == Source::Custom;
        b_custom
            .cmp(&a_custom)
            .then(
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then((b.end - b.start).cmp(&(a.end - a.start)))
    });

    let mut kept: Vec<CachedDetection> = Vec::new();
    for d in dets {
        let overlaps = kept.iter().any(|k| d.start < k.end && k.start < d.end);
        if !overlaps {
            kept.push(d);
        }
    }
    kept.sort_by_key(|d| d.start);
    kept
}
