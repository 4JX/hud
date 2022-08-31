use std::{collections::HashMap, num::ParseIntError};

use hudsucker::hyper::{Body, Request, Response};
use itertools::Itertools;
use reqwest_impersonate::StatusCode;
use serde::{Deserialize, Serialize};

const BASIC_AUTH_PREFIX: &str = "Basic ";

/// Shorthand to create an auth required response
pub(crate) fn res_auth_needed() -> Response<Body> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header("Proxy-Authenticate", "Basic")
        .body(Body::empty())
        .unwrap()
}

/// Determines wether the user has used valid credentials
/// Currently it doesn't do much of anything, edit to your liking
pub(crate) fn handle_auth(req: &Request<Body>) -> bool {
    let proxy_auth = req
        .headers()
        .get(hudsucker::hyper::header::PROXY_AUTHORIZATION);

    match proxy_auth {
        Some(auth) => {
            let auth_header_str = auth.to_str().unwrap();
            if auth_header_str.starts_with(BASIC_AUTH_PREFIX) {
                let session = Session::from_auth_header(auth_header_str);

                //TODO: Actually handle auth!
                if session.customer() == "user123" && session.password() == "foo" {
                    return true;
                }
            }

            false
        }
        None => false,
    }
}

/// Represents an active connection to the proxy that has included correctly formatted information
#[derive(Debug)]
struct Session {
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

impl TryFrom<SessionDataRaw> for SessionData {
    type Error = ParseIntError;

    fn try_from(value: SessionDataRaw) -> Result<Self, Self::Error> {
        let SessionDataRaw {
            customer,
            session_id,
            country,
            session_time,
        } = value;

        let parsed_session_time = session_time.parse::<usize>()?;

        Ok(SessionData {
            customer,
            session_id,
            country,
            session_time: parsed_session_time,
        })
    }
}

#[derive(Debug)]
struct SessionData {
    customer: String,
    session_id: String,
    country: String,
    session_time: usize,
}

#[allow(dead_code)]
impl Session {
    /// Creates a new session struct based on the information provided by the Proxy-Authorization header
    fn from_auth_header(auth_header_str: &str) -> Self {
        let base64_auth: String = auth_header_str
            .chars()
            .skip(BASIC_AUTH_PREFIX.len())
            .collect();
        let decoded = base64::decode(base64_auth).unwrap();
        let creds = std::str::from_utf8(&decoded).unwrap();

        let (username, password) = creds.rsplit_once(':').unwrap();
        let parsed_values: HashMap<&str, &str> = username.split('-').tuples::<(_, _)>().collect();

        let as_json = serde_json::to_string(&parsed_values).unwrap();
        let user_values_raw: SessionDataRaw = serde_json::from_str(&as_json).unwrap();

        Session {
            session_data: user_values_raw.try_into().unwrap(),
            password: password.to_string(),
        }
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
