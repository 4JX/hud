use std::{
    cmp::Eq,
    hash::Hash,
    time::{Duration, Instant},
};

use cached::{Cached, CanExpire, ExpiringValueCache};

mod client_storage;
mod session_storage;

pub use client_storage::ClientStorage;
use hudsucker::{
    hyper::{Body, Request},
    HttpContext,
};
pub use session_storage::SessionStorage;
use sha1::Digest;

// At least 10 mins between each flush
const EXPIRED_FLUSH_INTERVAL: Duration = Duration::from_secs(60 * 10);

#[allow(dead_code)]
#[derive(Clone)]
pub struct Storage<K: Hash + Eq, V> {
    inner: ExpiringValueCache<K, ExpiringValue<V>>,
    last_flush: Instant,
    flush_interval: Duration,
}

#[derive(Clone)]
pub struct ExpiringValue<T> {
    inner: T,
    expiry: Instant,
}

impl<T> CanExpire for ExpiringValue<T> {
    fn is_expired(&self) -> bool {
        Instant::now() > self.expiry
    }
}

impl<K: Hash + Eq + Clone, V> Storage<K, V> {
    pub fn new() -> Self {
        Self {
            inner: ExpiringValueCache::with_size(10000),
            last_flush: Instant::now(),
            flush_interval: EXPIRED_FLUSH_INTERVAL,
        }
    }

    pub fn set_with_duration(&mut self, k: K, v: V, d: Duration) -> Option<V> {
        let diff = Instant::now() - self.last_flush;
        if diff > self.flush_interval {
            self.inner.flush();
            self.last_flush = Instant::now();
        }

        let expiring = ExpiringValue {
            inner: v,
            expiry: Instant::now() + d,
        };

        self.inner.cache_set(k, expiring).map(|v| v.take())
    }

    pub fn get(&mut self, k: &K) -> Option<&V> {
        self.inner.cache_get(k).map(|v| v.get())
    }
}

impl<T> ExpiringValue<T> {
    fn take(self) -> T {
        self.inner
    }

    fn get(&self) -> &T {
        &self.inner
    }
}

/// Represents an unique identifier for a given IP and host
#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub struct ConnectionHash(String);

impl ConnectionHash {
    pub fn new(ctx: &HttpContext, request: &Request<Body>) -> Self {
        let host = request.uri().host().unwrap();

        let mut hasher = sha1::Sha1::new();

        hasher.update(ctx.client_addr.to_string());
        hasher.update(host);

        let finished = hasher.finalize();
        Self(hex::encode(finished))
    }
}
