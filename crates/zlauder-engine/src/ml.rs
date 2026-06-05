//! ML recognizer construction (`openai/privacy-filter` on a native-Rust Candle
//! CPU backend). This is the ONLY module that touches `presidio-classifier` /
//! Candle, so it is gated behind the `ml` feature; the rest of the engine wires
//! the recognizer in purely as an `Arc<dyn presidio_core::Recognizer>`.
//!
//! Both entry points are synchronous and heavy (model download + load). The
//! proxy calls them from a `spawn_blocking` task so the request executor is never
//! blocked, and `CandleBackend`'s loader drives `hf-hub` on its own scoped-thread
//! runtime, so it is safe to call from inside a Tokio context.

use std::sync::Arc;

use presidio_classifier::backends::{CandleBackend, CandleConfig};
use presidio_classifier::{Chunker, OPENAI_PRIVACY_FILTER, TokenClassifierRecognizer};
use presidio_core::Recognizer;

use crate::config::MlConfig;
use crate::error::EngineError;

/// Translate an `MlConfig` into the Candle backend's config. `prefer_gpu` only
/// matters if the crate was built with `cuda`/`metal`; otherwise it falls through
/// to CPU regardless (see `select_device`).
fn candle_config(cfg: &MlConfig) -> CandleConfig {
    CandleConfig {
        repo_id: cfg.model.clone(),
        revision: cfg.revision.clone(),
        prefer_gpu: cfg.prefer_gpu,
    }
}

/// Build the token-classification recognizer, downloading + loading the model
/// (cached under the standard `hf-hub` location). Heavy + blocking.
pub fn build_recognizer(cfg: &MlConfig) -> Result<Arc<dyn Recognizer>, EngineError> {
    let backend =
        CandleBackend::new(candle_config(cfg)).map_err(|e| EngineError::Ml(e.to_string()))?;
    let mut builder = TokenClassifierRecognizer::builder()
        .with_spec(&OPENAI_PRIVACY_FILTER)
        .with_backend(Arc::new(backend))
        // Sentence-like chunker so oversize fields are split, not rejected.
        .with_chunker(Chunker::for_openai_privacy_filter());
    if let Some(s) = cfg.min_score {
        builder = builder.with_min_score(s);
    }
    Ok(Arc::new(builder.build()))
}

/// Download + cache the model's weights/tokenizer/config without keeping it
/// loaded (constructs the backend, then drops it). Used by the explicit
/// `zlauder-proxy --download-model` pre-warm so a later `enable` is fast.
pub fn download(cfg: &MlConfig) -> Result<(), EngineError> {
    CandleBackend::new(candle_config(cfg)).map_err(|e| EngineError::Ml(e.to_string()))?;
    Ok(())
}
