use std::time::Duration;

use log::trace;
use reqwest_impersonate::{browser::ChromeVersion, Client};
use sha1::Digest;

use super::{ConnectionHash, Storage};
use crate::auth::Session;

#[allow(dead_code)]
#[derive(Clone)]
pub struct ClientStorage {
    inner: Storage<ClientHash, Client>,
}

impl ClientStorage {
    pub fn new() -> Self {
        Self {
            inner: Storage::new(),
        }
    }

    /// Get a client based on the [`ConnectionHash`]
    pub fn acquire_client(&mut self, client_hash: ClientHash, session: &Session) -> &mut Client {
        let f = || {
            reqwest_impersonate::Client::builder()
                .chrome_builder(ChromeVersion::V104)
                .build()
                .unwrap()
        };

        let dur = Duration::from_secs(session.session_time());

        let expiring = self.inner.get_or_set_with_duration(client_hash, f, dur);

        // If the session_time has changed, update the expiration time
        if expiring.duration != dur {
            expiring.set_duration(dur)
        }

        expiring.get_mut()
    }
}

/// Represents an unique identifier to get a client with
#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub struct ClientHash(String);

impl ClientHash {
    pub fn new(conn_hash: &ConnectionHash, session: &Session, route_type: &str) -> Self {
        let mut hasher = sha1::Sha1::new();

        hasher.update(conn_hash);
        hasher.update(session.session_id());
        hasher.update(session.password());
        hasher.update(route_type);

        let finished = hasher.finalize();

        let encoded = hex::encode(finished);

        trace!("{encoded}");

        Self(encoded)
    }
}
