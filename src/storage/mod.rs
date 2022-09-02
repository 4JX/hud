use std::{
    cmp::Eq,
    hash::Hash,
    time::{Duration, Instant},
};

use cached::{Cached, CanExpire, ExpiringValueCache};

mod client_storage;
mod session_storage;

pub use client_storage::{ClientHash, ClientStorage};
use hudsucker::{
    hyper::{Body, Request},
    HttpContext,
};
use log::trace;
pub use session_storage::SessionStorage;
use sha1::Digest;

// At least 10 mins between each flush
const EXPIRED_FLUSH_INTERVAL: Duration = Duration::from_secs(1);

#[allow(dead_code)]
#[derive(Clone)]
pub struct Storage<K: Hash + Eq, V> {
    inner: ExpiringValueCache<K, ExpiringValue<V>>,
    last_flush: Instant,
    flush_interval: Duration,
}

#[derive(Clone)]
struct ExpiringValue<T> {
    inner: T,
    created_at: Instant,
    duration: Duration,
}

impl<T> CanExpire for ExpiringValue<T> {
    fn is_expired(&self) -> bool {
        Instant::now() > (self.created_at + self.duration)
    }
}

impl<K: Hash + Eq + Clone, V> Storage<K, V> {
    fn new() -> Self {
        Self {
            inner: ExpiringValueCache::with_size(10000),
            last_flush: Instant::now(),
            flush_interval: EXPIRED_FLUSH_INTERVAL,
        }
    }

    fn set_with_duration(&mut self, k: K, v: V, d: Duration) -> Option<V> {
        self.flush();

        let expiring = ExpiringValue {
            inner: v,
            created_at: Instant::now(),
            duration: d,
        };

        self.inner.cache_set(k, expiring).map(|v| v.take())
    }

    fn get(&mut self, k: &K) -> Option<&V> {
        self.inner.cache_get(k).map(|v| v.get())
    }

    fn get_or_set_with_duration<F: FnOnce() -> V>(
        &mut self,
        k: K,
        f: F,
        d: Duration,
    ) -> &mut ExpiringValue<V> {
        self.flush();

        let wrapper = || ExpiringValue {
            inner: f(),
            created_at: Instant::now(),
            duration: d,
        };

        self.inner.cache_get_or_set_with(k, wrapper)
    }

    fn flush(&mut self) {
        let diff = Instant::now() - self.last_flush;
        if diff > self.flush_interval {
            self.inner.flush();
            self.last_flush = Instant::now();
        }
    }
}

impl<T> ExpiringValue<T> {
    fn take(self) -> T {
        self.inner
    }

    fn get(&self) -> &T {
        &self.inner
    }

    fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Resets the expiration time of the [`ExpiringValue`] with the new duration
    fn set_duration(&mut self, d: Duration) {
        self.created_at = Instant::now();
        self.duration = d;
    }
}

/// Represents an unique identifier for a given IP and host
#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub struct ConnectionHash(String);

impl AsRef<[u8]> for ConnectionHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl ConnectionHash {
    pub fn new(ctx: &HttpContext, request: &Request<Body>) -> Self {
        let host = request.uri().host().unwrap();

        let mut hasher = sha1::Sha1::new();

        hasher.update(ctx.client_addr.ip().to_string());
        hasher.update(host);

        let finished = hasher.finalize();

        let encoded = hex::encode(finished);

        trace!("{encoded}");

        Self(encoded)
    }
}
