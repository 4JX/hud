use std::{collections::HashMap, net::SocketAddr};

use error_stack::{bail, IntoReport, Report, Result, ResultExt};
use hudsucker::{
    hyper::{Body, Request},
    HttpContext,
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const BASIC_AUTH_PREFIX: &str = "Basic ";

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

                // TODO: Actually handle auth!
                if session.customer() == "user123" && session.password() == "foo" {
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
#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
struct SessionData {
    customer: String,
    session_id: String,
    country: String,
    session_time: u64,
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

        let username_split = username.split('-');

        let count = username_split.clone().count();

        if count % 2 != 0 {
            bail!(Report::new(ParseAuthError).attach_printable(
                format! {"Expected even number of elements in username, found {count}"},
            ));
        }

        let parsed_values: HashMap<&str, &str> = username_split.tuples::<(_, _)>().collect();

        let as_json = serde_json::to_string(&parsed_values)
            .into_report()
            .change_context(ParseAuthError)?;

        let raw: SessionDataRaw = serde_json::from_str(&as_json)
            .into_report()
            .change_context(ParseAuthError)?;

        // Verbosity moment
        check_param_length(&raw.customer, 0, 32)
            .attach_printable("customer")
            .change_context(ParseAuthError)?;
        check_param_length(&raw.session_id, 0, 32)
            .attach_printable("session_id")
            .change_context(ParseAuthError)?;
        check_param_length(&raw.country, 0, 32)
            .attach_printable("country")
            .change_context(ParseAuthError)?;
        check_param_length(&raw.session_time, 0, 32)
            .attach_printable("session_time")
            .change_context(ParseAuthError)?;
        check_param_length(password, 0, 64)
            .attach_printable("password")
            .change_context(ParseAuthError)?;

        let raw_session_time = raw.session_time;
        Ok(Session {
            addr: ctx.client_addr,
            session_data: SessionData {
                customer: raw.customer,
                session_id: raw.session_id,
                country: raw.country,
                session_time: raw_session_time
                    .parse::<u64>()
                    .into_report()
                    .attach_printable(format!("Invalid session time {raw_session_time}"))
                    .change_context(ParseAuthError)?,
            },
            password: password.to_string(),
        })
    }

    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    pub fn customer(&self) -> &str {
        &self.session_data.customer
    }

    pub fn session_id(&self) -> &str {
        &self.session_data.session_id
    }

    pub fn country(&self) -> &str {
        &self.session_data.country
    }

    pub fn session_time(&self) -> u64 {
        self.session_data.session_time
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

#[derive(Debug, Error)]
#[error(
    "The string passed did not fit in the specified bounds. Expected {min}-{max}, found {found}"
)]
struct ParamLengthError {
    min: usize,
    max: usize,
    found: usize,
}

fn check_param_length(s: &str, min: usize, max: usize) -> Result<(), ParamLengthError> {
    let len = s.len();
    if s.is_empty() || len > max {
        bail!(Report::new(ParamLengthError {
            min,
            max,
            found: len
        }));
    }

    Ok(())
}
