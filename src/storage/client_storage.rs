use std::time::Duration;

use reqwest_impersonate::{ChromeVersion, Client};
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
        ClientStorage {
            inner: Storage::new(),
        }
    }

    /// Get a client based on the [ConnectionHash]
    pub fn acquire_client(&mut self, client_hash: ClientHash, session: &Session) -> &mut Client {
        dbg!(&client_hash);

        let f = || {
            dbg!("NEW CLIENT CREATED");
            reqwest_impersonate::Client::builder()
                .chrome_builder(ChromeVersion::V104)
                .build()
                .unwrap()
        };

        let dur = Duration::from_secs(session.session_time());

        self.inner.get_or_set_with_duration(client_hash, f, dur)
    }
}

/// Represents an unique identifier to get a client with
#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub struct ClientHash(String);

impl ClientHash {
    pub fn new(conn_hash: &ConnectionHash, session: &Session, route_type: &str) -> Self {
        let mut hasher = sha1::Sha1::new();

        dbg!(
            conn_hash,
            session.session_id(),
            session.password(),
            route_type
        );
        hasher.update(conn_hash);
        hasher.update(session.session_id());
        hasher.update(session.password());
        hasher.update(route_type);

        let finished = hasher.finalize();
        Self(hex::encode(finished))
    }
}
