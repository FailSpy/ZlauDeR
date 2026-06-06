//! OpenAI Responses API boundary.
//!
//! TODO: replace this explicit passthrough with typed request/response/SSE
//! masking when `openai-wire` grows Responses API wire primitives.

use axum::extract::{Request, State};
use axum::response::Response;

use crate::{routes, state::AppState};

/// `/v1/responses` — intentionally passthrough for now.
pub async fn responses(State(st): State<AppState>, req: Request) -> Response {
    tracing::debug!(
        "OpenAI Responses API passthrough: masking is not implemented for /v1/responses"
    );
    routes::relay_verbatim(&st, req).await
}
