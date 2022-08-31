//! Holds functions to ease conversions between the hudsucker and reqwest types

use hudsucker::hyper::{Body, Response};

/// Converts a reqwest request to a hudsucker one.
pub(crate) async fn response_reqwest_to_hud(
    mut reqwest_res: reqwest_impersonate::Response,
) -> Response<Body> {
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

    builder
        .body(Body::from(reqwest_res.bytes().await.unwrap()))
        .unwrap()
}
