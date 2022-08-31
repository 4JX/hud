use hudsucker::{
    async_trait::async_trait,
    hyper::{http::uri::Scheme, Body, Request, Response},
    HttpContext, HttpHandler, RequestOrResponse,
};
use log::warn;
use reqwest_impersonate::{header::HOST, ChromeVersion, Method};

use crate::{
    auth::handle_auth,
    convert::response_reqwest_to_hud,
    response,
    storage::{ClientStorage, ConnectionHash, SessionStorage},
};

#[derive(Clone)]
pub struct ProxyHandler {
    client_storage: ClientStorage,
    session_storage: SessionStorage,
}

impl ProxyHandler {
    pub fn new() -> Self {
        ProxyHandler {
            client_storage: ClientStorage::new(),
            session_storage: SessionStorage::new(),
        }
    }
}

#[async_trait]
impl HttpHandler for ProxyHandler {
    async fn handle_request(&mut self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        let conn_hash = ConnectionHash::new(ctx, &req);

        if req.method() == Method::CONNECT {
            match handle_auth(ctx, &req) {
                Ok(session) => {
                    self.session_storage.insert_session(conn_hash, session);
                    // Allow the connection to pass through
                    RequestOrResponse::Request(req)
                }

                Err(err) => {
                    warn!("Proxy connect failed\n{err:?}");

                    RequestOrResponse::Response(response::auth_needed())
                }
            }
        } else if let Some(_session) = self.session_storage.get_session(&conn_hash) {
            let mut reqwest_req: reqwest_impersonate::Request = req.try_into().unwrap();

            // Remove redundant HOST header to keep the fingerprint in check
            reqwest_req.headers_mut().remove(HOST);

            // *reqwest_req.headers_mut() = create_headers();

            self.client_storage.acquire_client(ctx, &reqwest_req);

            let client_imp = reqwest_impersonate::Client::builder()
                .chrome_builder(ChromeVersion::V104)
                .build()
                .unwrap();

            let reqwest_res = client_imp.execute(reqwest_req).await.unwrap();

            let res = response_reqwest_to_hud(reqwest_res).await.unwrap();

            RequestOrResponse::Response(res)
        } else {
            // There is no currently active session for the given ConnectionHash
            // Either the request is being made using http or something went wrong when authenticating
            // TODO: Determine if letting http through is desired
            if let Some(scheme) = req.uri().scheme() {
                if scheme == &Scheme::HTTP {
                    return RequestOrResponse::Request(req);
                }
            }

            RequestOrResponse::Response(response::unauthorized())
        }
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        res
    }
}
