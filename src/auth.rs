use std::net::SocketAddr;

use error_stack::{IntoReport, Report, Result, ResultExt};
use hudsucker::{
    hyper::{Body, Request},
    HttpContext,
};

use thiserror::Error;

const BASIC_AUTH_PREFIX: &str = "Basic ";

#[derive(Debug, Error)]
pub enum CreateSessionError {
    #[error("Could not extract valid data from the Proxy-Authorization header")]
    MalformedHeader,
    #[error("No authorization header was provided")]
    NoAuthHeader,
}

/// Creates a new [Session] based on the provided authorization information
/// Currently it doesn't do much of anything, edit to your liking
pub fn handle_auth(ctx: &HttpContext, req: &Request<Body>) -> Result<Session, CreateSessionError> {
    let proxy_auth = req
        .headers()
        .get(hudsucker::hyper::header::PROXY_AUTHORIZATION);

    match proxy_auth {
        Some(auth) => {
            let auth_header_str = auth
                .to_str()
                .into_report()
                .change_context(CreateSessionError::MalformedHeader)?;

            if auth_header_str.starts_with(BASIC_AUTH_PREFIX) {
                let session = Session::new(ctx, auth_header_str)
                    .change_context(CreateSessionError::MalformedHeader)?;

                return Ok(session);
            }

            Err(Report::new(CreateSessionError::MalformedHeader)
                .attach_printable("Unsupported authorization type".to_string()))
        }
        None => Err(Report::new(CreateSessionError::NoAuthHeader)),
    }
}

/// Represents an active connection to the proxy that has included correctly
/// formatted information
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Session {
    addr: SocketAddr,
    username: String,
    password: String,
}

#[derive(Debug, Error)]
#[error("Could not parse session data")]
struct ParseAuthError;

impl Session {
    /// Creates a new session struct based on the information provided by the
    /// Proxy-Authorization header
    fn new(ctx: &HttpContext, auth_header_str: &str) -> Result<Self, ParseAuthError> {
        let base64_auth: String = auth_header_str
            .chars()
            .skip(BASIC_AUTH_PREFIX.len())
            .collect();

        let decoded = base64::decode(base64_auth)
            .into_report()
            .change_context(ParseAuthError)?;

        let creds = std::str::from_utf8(&decoded)
            .into_report()
            .change_context(ParseAuthError)?;

        let (username, password) = creds.rsplit_once(':').ok_or_else(|| {
            Report::new(ParseAuthError).attach_printable(format!(
                "Credentials \"{creds}\" are not correctly formatted"
            ))
        })?;

        Ok(Self {
            addr: ctx.client_addr,
            username: username.to_string(),
            password: password.to_string(),
        })
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}
