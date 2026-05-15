// SPDX-License-Identifier: AGPL-3.0-or-later
//! axum router assembly.

use axum::routing::{get, post};
use axum::Router;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::http::{health, top_up, AppState};

/// Build the axum router for the funder service.
///
/// `body_size_limit_bytes` caps every request body. The default
/// (16 KB) is well above the ~1 KB a well-formed `TopUpRequest`
/// needs; bumps must be justified.
pub fn router(state: AppState, body_size_limit_bytes: usize) -> Router {
    Router::new()
        .route("/funder/v1/top-up", post(top_up::handle))
        .route("/funder/v1/health", get(health::handle))
        .layer(RequestBodyLimitLayer::new(body_size_limit_bytes))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
