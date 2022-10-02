use std::time::Duration;

use super::{ConnectionHash, Storage};
use crate::auth::Session;

pub const SESSION_TIME: Duration = Duration::from_secs(5 * 60);
#[allow(dead_code)]
#[derive(Clone)]
pub struct SessionStorage {
    inner: Storage<ConnectionHash, Session>,
}

impl SessionStorage {
    pub fn new() -> Self {
        Self {
            inner: Storage::new(),
        }
    }

    /// Insert a new [`Session`] and get the old one if it exists for the given
    /// [`ConnectionHash`]
    pub fn insert_session(
        &mut self,
        conn_hash: ConnectionHash,
        session: Session,
    ) -> Option<Session> {
        self.inner
            .set_with_duration(conn_hash, session, SESSION_TIME)
    }

    /// Get a [`Session`] for the given [`ConnectionHash`]
    pub fn get_session(&mut self, conn_hash: &ConnectionHash) -> Option<&Session> {
        self.inner.get(conn_hash)
    }
}
