use std::sync::Arc;

use cached::async_sync::Mutex;
use hudsucker::{
    async_trait::async_trait,
    hyper::{http::uri::Scheme, Body, Request, Response, Uri},
    HttpContext, HttpHandler, RequestOrResponse,
};
use log::{trace, warn};
use reqwest_impersonate::{
    header::{ACCEPT, ACCEPT_ENCODING, HOST},
    Method,
};

use crate::{
    auth::handle_auth,
    convert::response_reqwest_to_hud,
    response,
    storage::{ClientHash, ClientStorage, ConnectionHash, SessionStorage},
};

#[derive(Clone)]
pub struct ProxyHandler {
    client_storage: Arc<Mutex<ClientStorage>>,
    session_storage: Arc<Mutex<SessionStorage>>,
}

impl ProxyHandler {
    pub fn new(
        client_storage: Arc<Mutex<ClientStorage>>,
        session_storage: Arc<Mutex<SessionStorage>>,
    ) -> Self {
        Self {
            client_storage,
            session_storage,
        }
    }
}

#[async_trait]
impl HttpHandler for ProxyHandler {
    async fn handle_request(&mut self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        trace!("Processing incoming request");

        let conn_hash = ConnectionHash::new(ctx, &req);

        if req.method() == Method::CONNECT {
            match handle_auth(ctx, &req) {
                Ok(session) => {
                    self.session_storage
                        .lock()
                        .await
                        .insert_session(conn_hash, session);

                    trace!("CONNECT successful");

                    // Allow the connection to pass through
                    RequestOrResponse::Request(req)
                }

                Err(err) => {
                    warn!("Proxy connect auth failed\n{err:?}");

                    RequestOrResponse::Response(response::auth_needed())
                }
            }
        } else if let Some(session) = self.session_storage.lock().await.get_session(&conn_hash) {
            let client_hash = ClientHash::new(&conn_hash, session);

            let mut reqwest_req: reqwest_impersonate::Request = req.try_into().unwrap();

            // Remove redundant headers to keep the fingerprint in check
            reqwest_req.headers_mut().remove(HOST);
            reqwest_req.headers_mut().remove(ACCEPT);
            reqwest_req.headers_mut().remove(ACCEPT_ENCODING);

            let mut storage = self.client_storage.lock().await;

            let client = storage.acquire_client(client_hash);

            match client.execute(reqwest_req).await {
                Ok(res) => {
                    let http_res = response_reqwest_to_hud(res).await.unwrap();

                    RequestOrResponse::Response(http_res)
                }
                Err(_) => RequestOrResponse::Response(response::internal_server_error()),
            }
        } else {
            // There is no currently active session for the given ConnectionHash
            // Either the request is being made using http or something went wrong when
            // authenticating
            if let Some(scheme) = req.uri().scheme() {
                // If it is an http request, attempt to redirect to the https site
                if scheme == &Scheme::HTTP {
                    trace!("Url provided is using HTTP, redirecting to HTTPS");

                    let http_uri = req.uri().clone();
                    let mut parts = http_uri.into_parts();
                    parts.scheme = Some(Scheme::HTTPS);
                    let https_uri = Uri::from_parts(parts).unwrap();

                    return RequestOrResponse::Response(response::permanent_redirect(&https_uri));
                }
            }

            trace!("Could not authorize user");

            RequestOrResponse::Response(response::auth_needed())
        }
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        res
    }
}
