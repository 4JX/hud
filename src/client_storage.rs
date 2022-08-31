use std::time::{Duration, Instant};

use cached::{CanExpire, ExpiringValueCache};
use hudsucker::HttpContext;
use log::info;
use reqwest_impersonate::{Client, Request};
use sha1::Digest;

// At least 10 mins between each flush
const EXPIRED_FLUSH_INTERVAL: Duration = Duration::from_secs(60 * 10);

#[allow(dead_code)]
#[derive(Clone)]
pub struct ClientStorage {
    inner: ExpiringValueCache<String, ExpiringValue<Client>>,
    last_flush: Instant,
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

impl ClientStorage {
    pub fn new() -> Self {
        ClientStorage {
            inner: ExpiringValueCache::with_size(10000),
            last_flush: Instant::now(),
        }
    }

    /// Get a client based on the session_id and host
    pub fn acquire_client(&mut self, ctx: &HttpContext, request: &Request) {
        let diff = Instant::now() - self.last_flush;
        if diff > EXPIRED_FLUSH_INTERVAL {
            self.inner.flush();
            self.last_flush = Instant::now();

            info!("Client cache flushed");
        }

        let mut hasher = sha1::Sha1::new();

        hasher.update(ctx.client_addr.to_string());

        let host = request.url().host().unwrap();
        hasher.update(host.to_string());

        let finished = hasher.finalize();
        let sha1 = hex::encode(finished);

        dbg!(sha1);
    }
}
