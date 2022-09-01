use std::{net::SocketAddr, sync::Arc};

use cached::async_sync::Mutex;
use hudsucker::{certificate_authority::RcgenAuthority, Proxy};
use log::error;

use super::ProxyHandler;
use crate::storage::{ClientStorage, SessionStorage};

// Wraps a proxy to provide an in-memory cache
pub struct ProxyWrapper {
    bind_addr: SocketAddr,
    client_storage: Arc<Mutex<ClientStorage>>,
    session_storage: Arc<Mutex<SessionStorage>>,
}

impl ProxyWrapper {
    pub fn new() -> Self {
        Self {
            client_storage: Arc::new(Mutex::new(ClientStorage::new())),
            session_storage: Arc::new(Mutex::new(SessionStorage::new())),
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 3000)),
        }
    }

    pub async fn start(&self, ca: RcgenAuthority) {
        let proxy = Proxy::builder()
            .with_addr(self.bind_addr)
            .with_rustls_client()
            .with_ca(ca)
            .with_http_handler(ProxyHandler::new(
                self.client_storage.clone(),
                self.session_storage.clone(),
            ))
            .build();

        if let Err(e) = proxy.start(shutdown_signal()).await {
            error!("{}", e);
        }
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}
