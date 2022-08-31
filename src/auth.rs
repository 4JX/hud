use std::{collections::HashMap, net::SocketAddr};

use error_stack::{IntoReport, Report, Result, ResultExt};
use hudsucker::{
    hyper::{Body, Request, Response},
    HttpContext,
};
use itertools::Itertools;
use reqwest_impersonate::StatusCode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const BASIC_AUTH_PREFIX: &str = "Basic ";

/// Shorthand to create an auth required response
pub fn res_auth_needed() -> Response<Body> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header("Proxy-Authenticate", "Basic")
        .body(Body::empty())
        .unwrap()
}

#[derive(Debug, Error)]
pub enum CreateSessionError {
    #[error("Could not extract valid data from the Proxy-Authorization header")]
    MalformedHeader,
    #[error("Failed login attempt for user \"{customer}\" with password \"{password}\" ({addr})")]
    Unauthorized {
        addr: String,
        customer: String,
        password: String,
    },
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

                //TODO: Actually handle auth!
                let authorized = true;
                if authorized {
                    return Ok(session);
                } else {
                    return Err(Report::new(CreateSessionError::Unauthorized {
                        addr: session.addr().to_string(),
                        customer: session.customer().to_string(),
                        password: session.password().to_string(),
                    }));
                }
            }

            Err(Report::new(CreateSessionError::MalformedHeader)
                .attach_printable("Unsupported authorization type".to_string()))
        }
        None => Err(Report::new(CreateSessionError::NoAuthHeader)),
    }
}

/// Represents an active connection to the proxy that has included correctly formatted information
#[allow(dead_code)]
#[derive(Debug)]
pub struct Session {
    addr: SocketAddr,
    session_data: SessionData,
    password: String,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
struct SessionDataRaw {
    customer: String,
    session_id: String,
    country: String,
    session_time: String,
}

#[derive(Debug)]
struct SessionData {
    customer: String,
    session_id: String,
    country: String,
    session_time: usize,
}

#[derive(Debug, Error)]
#[error("Could not parse session data")]
struct ParseAuthError;
#[allow(dead_code)]
impl Session {
    /// Creates a new session struct based on the information provided by the Proxy-Authorization header
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

        let parsed_values: HashMap<&str, &str> = username.split('-').tuples::<(_, _)>().collect();

        let as_json = serde_json::to_string(&parsed_values)
            .into_report()
            .change_context(ParseAuthError)?;
        let raw: SessionDataRaw = serde_json::from_str(&as_json)
            .into_report()
            .change_context(ParseAuthError)?;

        let raw_session_time = raw.session_time;
        Ok(Session {
            addr: ctx.client_addr,
            session_data: SessionData {
                customer: raw.customer,
                session_id: raw.session_id,
                country: raw.country,
                session_time: raw_session_time
                    .parse::<usize>()
                    .into_report()
                    .attach_printable(format!("Invalid session time {raw_session_time}"))
                    .change_context(ParseAuthError)?,
            },
            password: password.to_string(),
        })
    }

    fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    fn customer(&self) -> &str {
        &self.session_data.customer
    }

    fn session_id(&self) -> &str {
        &self.session_data.session_id
    }

    fn country(&self) -> &str {
        &self.session_data.country
    }

    fn session_time(&self) -> usize {
        self.session_data.session_time
    }

    fn password(&self) -> &str {
        &self.password
    }
}
