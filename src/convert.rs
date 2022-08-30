//! Holds functions to ease conversions between the hudsucker and reqwest types

use std::str::FromStr;

use hudsucker::hyper::{body::to_bytes, Body, Request, Response};
use reqwest_impersonate::Url;

use crate::util::replace_headers;

/// Converts a hudsucker request to a reqwest one.
pub(crate) async fn request_hud_to_reqwest(
    req: Request<Body>,
) -> reqwest_impersonate::blocking::Request {
    let mut reqwest_req = reqwest_impersonate::blocking::Request::new(
        req.method().clone(),
        Url::from_str(&req.uri().to_string()).unwrap(),
    );

    replace_headers(reqwest_req.headers_mut(), req.headers().clone());

    *reqwest_req.version_mut() = req.version();

    let bytes = to_bytes(req.into_body()).await.unwrap();
    let reqwest_body = reqwest_impersonate::blocking::Body::from(bytes);
    *reqwest_req.body_mut() = Some(reqwest_body);

    reqwest_req
}

/// Converts a reqwest request to a hudsucker one.
pub(crate) fn response_reqwest_to_hud(
    reqwest_res: reqwest_impersonate::blocking::Response,
) -> Response<Body> {
    let mut builder = Response::builder()
        .status(reqwest_res.status())
        .version(reqwest_res.version());

    if let Some(headers) = builder.headers_mut() {
        replace_headers(headers, reqwest_res.headers().clone());
    }

    builder
        .body(Body::from(reqwest_res.bytes().unwrap()))
        .unwrap()
}
