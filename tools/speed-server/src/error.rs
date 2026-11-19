// SPDX-License-Identifier: GPL-3.0-or-later
//! HTTP error responses.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use crate::limits::Denied;

/// An error returned to the client as a small JSON document.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// Invalid query parameter (400).
    #[error("{0}")]
    BadRequest(String),
    /// Upload larger than the configured maximum (413).
    #[error("upload exceeds the maximum of {max} bytes")]
    PayloadTooLarge {
        /// Configured maximum.
        max: u64,
    },
    /// The transfer exceeded its maximum duration (408).
    #[error("transfer exceeded the maximum duration")]
    Timeout,
    /// A protection limit was hit (429).
    #[error("{0}")]
    Limited(#[from] Denied),
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let message = self.to_string();
        let (status, code, retry_after) = match &self {
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request", None),
            ApiError::PayloadTooLarge { .. } => {
                (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", None)
            }
            ApiError::Timeout => (StatusCode::REQUEST_TIMEOUT, "request_timeout", None),
            ApiError::Limited(d) => (
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_requests",
                Some(d.retry_after_secs()),
            ),
        };
        let mut resp = (
            status,
            Json(ErrorBody {
                error: code,
                message,
            }),
        )
            .into_response();
        let headers = resp.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if let Some(secs) = retry_after {
            headers.insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        if matches!(self, ApiError::PayloadTooLarge { .. }) {
            // The unread request body must not be mistaken for the start of the next request.
            headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
        }
        resp
    }
}
