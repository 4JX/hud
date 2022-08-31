//! Holds functions to ease conversions between the hudsucker and reqwest types

use error_stack::{IntoReport, Result, ResultExt};
use hudsucker::hyper::{Body, Response};

use thiserror::Error;

#[derive(Debug, Error)]
#[error("Could not convert between types")]
pub struct ConversionError;

/// Converts a reqwest request to a hudsucker one.
pub async fn response_reqwest_to_hud(
    mut reqwest_res: reqwest_impersonate::Response,
) -> Result<Response<Body>, ConversionError> {
    let mut builder = Response::builder()
        .status(reqwest_res.status())
        .version(reqwest_res.version());

    // We are discarding the reqwest response anyways, so lets just be greedy
    if let Some(headers) = builder.headers_mut() {
        std::mem::swap(headers, reqwest_res.headers_mut());
    }

    if let Some(extensions) = builder.extensions_mut() {
        std::mem::swap(extensions, reqwest_res.extensions_mut());
    }
    let url = reqwest_res.url().clone();

    let body_bytes = reqwest_res
        .bytes()
        .await
        .into_report()
        .attach_printable(format! {"Could not get body bytes for a request to {url}"})
        .change_context(ConversionError)?;

    builder
        .body(Body::from(body_bytes))
        .into_report()
        .change_context(ConversionError)
}
