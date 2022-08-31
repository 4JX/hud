use hudsucker::hyper::{Body, Response};
use reqwest_impersonate::StatusCode;

/// Shorthand to create an auth required response
pub fn auth_needed() -> Response<Body> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header("Proxy-Authenticate", "Basic")
        .body(Body::empty())
        .unwrap()
}

/// Shorthand to create an unauthorized response
pub fn unauthorized() -> Response<Body> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(Body::empty())
        .unwrap()
}
