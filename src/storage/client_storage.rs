use hudsucker::HttpContext;
use reqwest_impersonate::{Client, Request};
use sha1::Digest;

use super::Storage;

#[allow(dead_code)]
#[derive(Clone)]
pub struct ClientStorage {
    inner: Storage<String, Client>,
}

impl ClientStorage {
    pub fn new() -> Self {
        ClientStorage {
            inner: Storage::new(),
        }
    }

    /// Get a client based on the session_id and host
    pub fn acquire_client(&mut self, ctx: &HttpContext, request: &Request) {
        let mut hasher = sha1::Sha1::new();

        hasher.update(ctx.client_addr.to_string());

        let host = request.url().host().unwrap();
        hasher.update(host.to_string());

        let finished = hasher.finalize();
        let sha1 = hex::encode(finished);

        dbg!(sha1);
    }
}
