use hudsucker::{
    async_trait::async_trait,
    hyper::{Body, Request, Response},
    HttpContext, HttpHandler, RequestOrResponse,
};
use log::warn;
use reqwest_impersonate::{ChromeVersion, Method};

use crate::{
    auth::{self, handle_auth},
    convert::response_reqwest_to_hud,
};

#[derive(Clone)]
pub struct ProxyHandler;

#[async_trait]
impl HttpHandler for ProxyHandler {
    async fn handle_request(&mut self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        let session_result = handle_auth(ctx, &req);

        if req.method() == Method::CONNECT {
            match session_result {
                Ok(_) => {
                    // Allow the connection to pass through
                    return RequestOrResponse::Request(req);
                }
                Err(err) => {
                    warn!("Proxy connect failed\n{err:?}");

                    return RequestOrResponse::Response(auth::res_auth_needed());
                }
            }
        };

        let client_imp = reqwest_impersonate::Client::builder()
            .chrome_builder(ChromeVersion::V104)
            .build()
            .unwrap();

        let reqwest_req: reqwest_impersonate::Request = req.try_into().unwrap();

        let reqwest_res = client_imp.execute(reqwest_req).await.unwrap();

        let res = response_reqwest_to_hud(reqwest_res).await.unwrap();

        RequestOrResponse::Response(res)
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        res
    }
}
