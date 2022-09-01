use hudsucker::hyper::{Body, Response, Uri};
use reqwest_impersonate::{
    header::{LOCATION, PROXY_AUTHENTICATE},
    StatusCode,
};

/// Shorthand to create an auth required response
pub fn auth_needed() -> Response<Body> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header(PROXY_AUTHENTICATE, "Basic")
        .body(Body::empty())
        .unwrap()
}

/// Shorthand to create a permanent redirect response
pub fn permanent_redirect(req: Uri) -> Response<Body> {
    Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header(LOCATION, req.to_string())
        .body(Body::empty())
        .unwrap()
}

/// Shorthand to create an internal server error response
pub fn internal_server_error() -> Response<Body> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::empty())
        .unwrap()
}
