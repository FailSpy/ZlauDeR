//! Engine configuration: profiles, entity categories, operators, allow-list, and
//! custom rules. Ported (trimmed) from orchestr8-privacy `config.rs`.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::surface::Surface;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Strict,
    #[default]
    Balanced,
    Minimal,
    DevelopmentSafe,
}

impl Profile {
    pub fn default_threshold(self) -> f32 {
        match self {
            Profile::Strict => 0.3,
            Profile::Balanced => 0.5,
            Profile::DevelopmentSafe => 0.6,
            Profile::Minimal => 0.8,
        }
    }

    pub fn default_categories(self) -> HashSet<Category> {
        use Category::*;
        let v: &[Category] = match self {
            Profile::Strict => &[Secrets, Financial, Identity, Contact, Personal],
            Profile::Balanced => &[Secrets, Financial, Identity, Contact],
            Profile::Minimal => &[Secrets, Financial],
            Profile::DevelopmentSafe => &[Secrets],
        };
        v.iter().copied().collect()
    }

    pub fn default_operator(self) -> Operator {
        match self {
            Profile::Strict => Operator::Redact,
            _ => Operator::Token,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Secrets,
    Financial,
    Identity,
    Contact,
    Personal,
}

impl Category {
    /// Entity-type strings (matching `presidio_core::EntityType`'s `Display`) that
    /// belong to this category.
    pub fn entity_types(self) -> &'static [&'static str] {
        match self {
            Category::Secrets => &[
                "API_KEY",
                "AWS_ACCESS_KEY",
                "AWS_SECRET_KEY",
                "AZURE_KEY",
                "GCP_API_KEY",
                "PRIVATE_KEY",
                "JWT",
            ],
            Category::Financial => &[
                "CREDIT_CARD",
                "IBAN",
                "CRYPTO_WALLET",
                "CRYPTO_ADDRESS",
                // Canonical `EntityType` Display for a US bank account is
                // `US_BANK_NUMBER` (`US_BANK_ACCOUNT` is only a parse alias); the
                // ML model's `account_number` label maps here, so this must be the
                // canonical string or those detections would be silently dropped.
                "US_BANK_NUMBER",
                "US_ROUTING_NUMBER",
            ],
            Category::Identity => &[
                "US_SSN",
                "US_ITIN",
                "NATIONAL_ID",
                "PASSPORT",
                "US_PASSPORT",
                "UK_PASSPORT",
                "DRIVER_LICENSE",
                "US_DRIVER_LICENSE",
                "UK_DRIVING_LICENCE",
                "US_MEDICAL_LICENSE",
                "US_NPI",
                "US_MBI",
                "UK_NHS",
                "UK_NINO",
            ],
            // URL relies on presidio's strict `UrlRecognizer` (the default since
            // its strict-mode change), which drops scheme-less `file.ext`/`opts.la`
            // false positives while keeping real URLs (scheme / www. / path).
            // DOMAIN stays OFF: its recognizer is still aggressive on filenames;
            // re-enable per-deployment via `entity_operators` if wanted.
            Category::Contact => &[
                "EMAIL_ADDRESS",
                "PHONE_NUMBER",
                "IP_ADDRESS",
                "URL",
                "MAC_ADDRESS",
            ],
            Category::Personal => &["PERSON", "LOCATION", "ORGANIZATION"],
        }
    }
    // NOTE: `DATE_TIME` (the ML model's `private_date` label) is deliberately not in
    // any category — dates are noisy (the regex `DateTimeRecognizer` is off by
    // default for the same reason), so the ML recognizer's date spans are dropped by
    // the category gate. It stays opt-in per deployment via an explicit
    // `entity_operators` entry (which `entity_enabled` honors). Locked by
    // `date_time_unmapped_by_default_but_opt_in` in lib.rs.
}

/// Scope of the deterministic token salt (DEFERRED behavior; the flag is parsed
/// but inert — see Component 3 of `glittery-bubbling-locket.md`).
/// - `Project` (today): one persisted per-project salt → cross-conversation token
///   determinism (stable Anthropic prompt-cache prefix on resume).
/// - `Conversation`: a per-conversation salt, keyed by a similarity-based content
///   fingerprint, so tokens do not correlate across conversations. NOT YET WIRED.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaltScope {
    #[default]
    Project,
    Conversation,
}

/// How widely a *burned* (pre-mask-exposed) value is redacted (DEFERRED behavior;
/// parsed but inert). `Leaf` redacts only the pre-ML occurrence; `Value` redacts
/// every occurrence (fully severs the token↔plaintext bridge at the cost of model
/// coherence). NOT YET WIRED.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExposureRedactionScope {
    #[default]
    Leaf,
    Value,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Operator {
    /// Reversible deterministic blake3 token (default).
    #[default]
    Token,
    /// Irreversible: replace with `[REDACTED]`.
    Redact,
    /// Irreversible: keep the last `from_end` chars, replace the rest with `char`.
    Mask { char: char, from_end: usize },
    /// Irreversible: `[ENTITY:hash]`.
    Hash,
    /// Detected but left verbatim (e.g. an allow-list-by-policy passthrough).
    Keep,
}

#[derive(Clone, Debug, Default)]
pub struct AllowList {
    pub exact: HashSet<String>,
    pub exact_ci: HashSet<String>,
    pub patterns: Vec<regex::Regex>,
}

impl AllowList {
    /// A small set of common safe words/hosts unlikely to be PII.
    pub fn with_common_words() -> Self {
        let mut al = Self::default();
        for w in ["Anthropic", "Claude", "127.0.0.1"] {
            al.add_exact(w);
        }
        al.add_exact_ci("localhost");
        al
    }

    pub fn is_allowed(&self, value: &str) -> bool {
        if self.exact.contains(value) {
            return true;
        }
        let lower = value.to_lowercase();
        if self.exact_ci.contains(&lower) {
            return true;
        }
        self.patterns.iter().any(|p| p.is_match(value))
    }

    pub fn add_exact(&mut self, v: impl Into<String>) {
        self.exact.insert(v.into());
    }

    pub fn add_exact_ci(&mut self, v: impl Into<String>) {
        self.exact_ci.insert(v.into().to_lowercase());
    }

    pub fn add_pattern(&mut self, p: regex::Regex) {
        self.patterns.push(p);
    }

    /// Build an allow-list from raw config strings (compiling pattern strings),
    /// seeded with the common-words defaults. Lets callers avoid a `regex` dep.
    pub fn from_specs(
        exact: Vec<String>,
        exact_ci: Vec<String>,
        patterns: Vec<String>,
    ) -> Result<Self, regex::Error> {
        let mut al = Self::with_common_words();
        for e in exact {
            al.add_exact(e);
        }
        for e in exact_ci {
            al.add_exact_ci(e);
        }
        for p in patterns {
            al.add_pattern(regex::Regex::new(&p)?);
        }
        Ok(al)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustomReplacement {
    pub pattern: String,
    pub entity_type: String,
    #[serde(default)]
    pub is_regex: bool,
    #[serde(default = "default_true")]
    pub case_sensitive: bool,
    #[serde(default)]
    pub priority: u32,
    #[serde(default)]
    pub literal_token: bool,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub apply_to_surfaces: Option<HashSet<Surface>>,
}

/// Optional ML recognizer config (`[engine.ml]`): the `openai/privacy-filter`
/// token classifier on a native-Rust Candle CPU backend. Plain serde — parsed
/// even by a regex-only (`--no-default-features`) build, which simply never loads
/// a model. Activation is hot: the proxy loads the model in the background when
/// `enabled` flips true (see `MlStatus`), so masking keeps running (regex-only)
/// while it loads.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlConfig {
    /// Whether the ML recognizer should be active. Loading happens in the
    /// background; until the model is `Ready`, masking is regex-only.
    #[serde(default)]
    pub enabled: bool,
    /// HuggingFace repo id of a privacy-filter–compatible checkpoint.
    #[serde(default = "default_ml_model")]
    pub model: String,
    /// Optional pinned revision (branch/tag/commit); `None` ⇒ `main`.
    #[serde(default)]
    pub revision: Option<String>,
    /// Recognizer score floor; `None` ⇒ the spec default (0.5). Distinct from the
    /// engine-wide `score_threshold`, which is *also* applied to ML detections.
    #[serde(default)]
    pub min_score: Option<f32>,
    /// Try CUDA/Metal before CPU. Default `false` (CPU); the GPU backends are not
    /// compiled in by default, so this falls through to CPU regardless.
    #[serde(default)]
    pub prefer_gpu: bool,
}

fn default_ml_model() -> String {
    "openai/privacy-filter".to_string()
}

impl Default for MlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model: default_ml_model(),
            revision: None,
            min_score: None,
            prefer_gpu: false,
        }
    }
}

impl MlConfig {
    /// Do the *model-affecting* params match `other` (ignoring `enabled`)? The
    /// proxy's reconcile uses this to decide whether a config change requires
    /// rebuilding the recognizer vs. a no-op.
    pub fn same_model_params(&self, other: &Self) -> bool {
        self.model == other.model
            && self.revision == other.revision
            && self.min_score == other.min_score
            && self.prefer_gpu == other.prefer_gpu
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EngineConfig {
    /// Master switch. When `false` the engine is a transparent passthrough on the
    /// mask (request) path — no detection, no tokens. Unmasking (response path)
    /// still runs, so tokens already in the transcript keep decoding. Toggled live
    /// via the proxy's control endpoint or persisted per scope.
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub profile: Profile,
    #[serde(default = "default_threshold")]
    pub score_threshold: f32,
    #[serde(default = "default_categories")]
    pub enabled_categories: HashSet<Category>,
    #[serde(default)]
    pub default_operator: Operator,
    #[serde(default)]
    pub entity_operators: HashMap<String, Operator>,
    #[serde(default = "default_language")]
    pub language: String,
    #[serde(default)]
    pub fail_closed: bool,
    #[serde(default)]
    pub disabled_surfaces: HashSet<Surface>,
    /// Not deserialized directly (`regex::Regex` is not `Deserialize`); the proxy
    /// config loader builds this from raw strings and assigns it.
    #[serde(skip)]
    pub allow_list: AllowList,
    #[serde(default)]
    pub custom_replacements: Vec<CustomReplacement>,
    /// Optional ML recognizer (`openai/privacy-filter`, CPU). Off by default.
    #[serde(default)]
    pub ml: MlConfig,

    // --- Detection cache (Component 1) ------------------------------------
    /// Max entries in the in-memory detection cache (LRU). `0` disables + clears
    /// it live. Default ~50k leaves; an empty detection list (the ~95% clean-leaf
    /// case) is a tiny value, so this bounds memory well below it in practice.
    #[serde(default = "default_cache_cap")]
    pub detection_cache_cap: usize,

    // --- Deferred Component-3 / persistence scaffolding (INERT) ------------
    // The fields below are parsed and documented but currently NON-FUNCTIONAL.
    // They reserve the config surface so enabling the behavior later is not a
    // breaking schema change. See `glittery-bubbling-locket.md` Component 3.
    /// (INERT) Persist the detection cache to disk across proxy restarts.
    #[serde(default)]
    pub detection_cache_persist: bool,
    /// (INERT) Path for the persisted detection cache (`None` ⇒ a default under the
    /// proxy state dir, when persistence is built).
    #[serde(default)]
    pub detection_cache_path: Option<String>,
    /// (INERT) On the ML `Ready` transition, redact ("burn") values exposed in
    /// plaintext during the pre-ML window instead of re-tokenizing them.
    #[serde(default)]
    pub redact_exposed_on_ml: bool,
    /// (INERT) Leaf- vs value-scoped burn (see [`ExposureRedactionScope`]).
    #[serde(default)]
    pub exposure_redaction_scope: ExposureRedactionScope,
    /// (INERT) Salt scope (see [`SaltScope`]).
    #[serde(default)]
    pub salt_scope: SaltScope,
    /// (INERT) Drop `thinking` blocks following a retroactive redaction (the model
    /// saw the value un-redacted while producing that opaque thinking).
    #[serde(default)]
    pub drop_contaminated_thinking: bool,
}

fn default_true() -> bool {
    true
}
fn default_threshold() -> f32 {
    0.5
}
fn default_language() -> String {
    "en".to_string()
}
fn default_categories() -> HashSet<Category> {
    Profile::Balanced.default_categories()
}
fn default_cache_cap() -> usize {
    50_000
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            profile: Profile::Balanced,
            score_threshold: 0.5,
            enabled_categories: Profile::Balanced.default_categories(),
            default_operator: Operator::Token,
            entity_operators: HashMap::new(),
            language: "en".to_string(),
            fail_closed: false,
            disabled_surfaces: HashSet::new(),
            allow_list: AllowList::with_common_words(),
            custom_replacements: Vec::new(),
            ml: MlConfig::default(),
            detection_cache_cap: default_cache_cap(),
            detection_cache_persist: false,
            detection_cache_path: None,
            redact_exposed_on_ml: false,
            exposure_redaction_scope: ExposureRedactionScope::default(),
            salt_scope: SaltScope::default(),
            drop_contaminated_thinking: false,
        }
    }
}

impl EngineConfig {
    /// A config seeded from a profile's threshold/categories/operator.
    pub fn for_profile(profile: Profile) -> Self {
        Self {
            profile,
            score_threshold: profile.default_threshold(),
            enabled_categories: profile.default_categories(),
            default_operator: profile.default_operator(),
            ..Self::default()
        }
    }

    /// Is `entity_type` subject to masking — either in an enabled category or with
    /// an explicit per-type operator override?
    pub fn entity_enabled(&self, entity_type: &str) -> bool {
        if self.entity_operators.contains_key(entity_type) {
            return true;
        }
        self.enabled_categories
            .iter()
            .any(|c| c.entity_types().contains(&entity_type))
    }

    /// Resolve the operator for an entity type (per-type override else default).
    pub fn operator_for(&self, entity_type: &str) -> Operator {
        self.entity_operators
            .get(entity_type)
            .copied()
            .unwrap_or(self.default_operator)
    }

    pub fn surface_enabled(&self, surface: Surface) -> bool {
        !self.disabled_surfaces.contains(&surface)
    }

    /// Fingerprint of every DETECTION-affecting input (folded into the cache key;
    /// audit #3/#6). A change here yields a fresh key space, so stale entries become
    /// unreachable with nothing to hand-invalidate.
    ///
    /// INCLUDES: the detector-version constant (audit #1 — bundled regex/custom
    /// recognizer code identity), score_threshold, language, enabled_categories, the
    /// entity_operators KEY SET (key *presence* gates detection via `entity_enabled`),
    /// custom_replacements (the patterns ARE the detection), and the allow_list.
    ///
    /// EXCLUDES (so these apply WITHOUT a cache miss): operator VALUES and
    /// `default_operator` (resolved at apply time), the `enabled` master switch and
    /// `disabled_surfaces` (their effect is the un-cached early-return passthrough),
    /// `fail_closed` (error policy, not detection), `profile` (only a seed for the
    /// derived fields), `ml` (covered by the separate `ml_fp`), and the cache /
    /// Component-3 scaffolding fields.
    ///
    /// All maps/sets are serialized in a canonical (sorted) order so semantically
    /// identical configs hash identically (audit #6). `custom_replacements` is hashed
    /// in Vec order because order can decide same-priority overlap ties.
    pub fn detection_fingerprint(&self) -> u64 {
        let mut h = blake3::Hasher::new();
        h.update(b"zlauder-policy-fp-v1");
        h.update(&crate::detect::DETECTOR_VERSION.to_le_bytes());
        h.update(&self.score_threshold.to_bits().to_le_bytes());
        h.update(self.language.as_bytes());
        h.update(&[0xff]);

        // enabled_categories — sorted by discriminant for canonical order.
        let mut cats: Vec<u8> = self.enabled_categories.iter().map(|c| *c as u8).collect();
        cats.sort_unstable();
        h.update(&cats);
        h.update(&[0xff]);

        // entity_operators KEYS only (values are apply-time) — sorted.
        let mut keys: Vec<&str> = self.entity_operators.keys().map(String::as_str).collect();
        keys.sort_unstable();
        for k in keys {
            h.update(k.as_bytes());
            h.update(&[0]);
        }
        h.update(&[0xff]);

        // custom_replacements — Vec order preserved (same-priority order matters).
        for c in &self.custom_replacements {
            fp_custom(&mut h, c);
        }
        h.update(&[0xff]);

        fp_allow_list(&mut h, &self.allow_list);

        let digest = h.finalize();
        u64::from_le_bytes(digest.as_bytes()[..8].try_into().expect("32-byte digest"))
    }
}

/// Canonical fingerprint contribution of one custom replacement rule.
fn fp_custom(h: &mut blake3::Hasher, c: &CustomReplacement) {
    h.update(c.pattern.as_bytes());
    h.update(&[0]);
    h.update(c.entity_type.as_bytes());
    h.update(&[0]);
    h.update(&[
        c.is_regex as u8,
        c.case_sensitive as u8,
        c.literal_token as u8,
    ]);
    h.update(&c.priority.to_le_bytes());
    match &c.token {
        Some(t) => {
            h.update(&[1]);
            h.update(t.as_bytes());
        }
        None => {
            h.update(&[0]);
        }
    };
    h.update(&[0]);
    match &c.apply_to_surfaces {
        None => {
            h.update(&[0]);
        }
        Some(set) => {
            h.update(&[1]);
            let mut surfs: Vec<u8> = set.iter().map(|s| *s as u8).collect();
            surfs.sort_unstable();
            h.update(&surfs);
        }
    };
    h.update(&[0xfe]);
}

/// Canonical fingerprint contribution of the allow-list (sets sorted; patterns by
/// source string, in declared order).
fn fp_allow_list(h: &mut blake3::Hasher, al: &AllowList) {
    let mut exact: Vec<&str> = al.exact.iter().map(String::as_str).collect();
    exact.sort_unstable();
    for e in exact {
        h.update(e.as_bytes());
        h.update(&[0]);
    }
    h.update(&[0xfe]);
    let mut ci: Vec<&str> = al.exact_ci.iter().map(String::as_str).collect();
    ci.sort_unstable();
    for e in ci {
        h.update(e.as_bytes());
        h.update(&[0]);
    }
    h.update(&[0xfe]);
    for p in &al.patterns {
        h.update(p.as_str().as_bytes());
        h.update(&[0]);
    }
}
