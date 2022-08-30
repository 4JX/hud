use std::collections::HashMap;

use hudsucker::hyper::{Body, Request, Response};
use itertools::Itertools;
use reqwest_impersonate::StatusCode;

const BASIC_AUTH_PREFIX: &str = "Basic ";

/// Determines wether the user has used valid credentials
/// Currently it doesn't do much, of anything, edit to your liking
pub(crate) fn handle_auth(req: &Request<Body>) -> bool {
    let auth = req
        .headers()
        .get(hudsucker::hyper::header::PROXY_AUTHORIZATION);

    match auth {
        Some(auth) => {
            let auth_str = auth.to_str().unwrap();
            if auth_str.starts_with(BASIC_AUTH_PREFIX) {
                let session = parse_auth(auth_str);

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
struct UserSession {
    user_values: UserSessionValues,
    password: String,
}

#[derive(Debug)]
struct UserSessionValues {
    customer: String,
    session_id: String,
    country: String,
    session_time: usize,
}

impl UserSession {
    fn from_parts(values: HashMap<String, String>, password: String) -> Self {
        UserSession {
            user_values: UserSessionValues::from_hashmap(values),
            password,
        }
    }

    fn customer(&self) -> &str {
        &self.user_values.customer
    }

    fn session_id(&self) -> &str {
        &self.user_values.session_id
    }

    fn country(&self) -> &str {
        &self.user_values.country
    }

    fn session_time(&self) -> usize {
        self.user_values.session_time
    }

    fn password(&self) -> &str {
        &self.password
    }
}

impl UserSessionValues {
    fn from_hashmap(mut values: HashMap<String, String>) -> Self {
        let customer = values.remove("customer").unwrap();
        let session_id = values.remove("session_id").unwrap();
        let country = values.remove("country").unwrap();
        let session_time = values
            .remove("session_time")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        Self {
            customer,
            session_id,
            country,
            session_time,
        }
    }
}

fn parse_auth(auth_str: &str) -> UserSession {
    let base64_auth: String = auth_str.chars().skip(BASIC_AUTH_PREFIX.len()).collect();
    let decoded = base64::decode(base64_auth).unwrap();
    let creds = std::str::from_utf8(&decoded).unwrap();
    let (user, pass) = creds.rsplit_once(':').unwrap();
    let mut parsed_values: HashMap<String, String> = HashMap::new();
    for (key, val) in user.split('-').tuples() {
        parsed_values.insert(key.to_string(), val.to_string());
    }

    UserSession::from_parts(parsed_values, pass.to_string())
}

pub(crate) fn res_auth_needed() -> Response<Body> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header("Proxy-Authenticate", "Basic")
        .body(Body::empty())
        .unwrap()
}
