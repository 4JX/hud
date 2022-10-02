use log::trace;
use reqwest_impersonate::{browser::ChromeVersion, Client};
use sha1::Digest;

use super::{session_storage::SESSION_TIME, ConnectionHash, Storage};
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
    pub fn acquire_client(&mut self, client_hash: ClientHash) -> &mut Client {
        let f = || {
            reqwest_impersonate::Client::builder()
                .chrome_builder(ChromeVersion::V104)
                .build()
                .unwrap()
        };

        let dur = SESSION_TIME;

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
    pub fn new(conn_hash: &ConnectionHash, session: &Session) -> Self {
        let mut hasher = sha1::Sha1::new();

        hasher.update(conn_hash);
        hasher.update(session.username());
        hasher.update(session.password());

        let finished = hasher.finalize();

        let encoded = hex::encode(finished);

        trace!("{encoded}");

        Self(encoded)
    }
}
