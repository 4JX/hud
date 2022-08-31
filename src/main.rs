use hudsucker::{
    async_trait::async_trait,
    certificate_authority::RcgenAuthority,
    hyper::{Body, Request, Response},
    rustls, HttpContext, HttpHandler, Proxy, RequestOrResponse,
};

use log::error;

use reqwest_impersonate::ChromeVersion;
use rustls_pemfile as pemfile;
use std::{fs, net::SocketAddr};

use crate::{auth::handle_auth, convert::response_reqwest_to_hud};

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

mod auth;
mod ca;
mod convert;

#[derive(Clone)]
struct ProxyHandler;

#[async_trait]
impl HttpHandler for ProxyHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        match req.method().as_str() {
            "CONNECT" => {
                if handle_auth(&req) {
                    RequestOrResponse::Request(req)
                } else {
                    RequestOrResponse::Response(auth::res_auth_needed())
                }
            }
            _ => {
                let client_imp = reqwest_impersonate::Client::builder()
                    .chrome_builder(ChromeVersion::V104)
                    .build()
                    .unwrap();

                let reqwest_req = req.try_into().unwrap();

                let reqwest_res = client_imp.execute(reqwest_req).await.unwrap();

                let res = response_reqwest_to_hud(reqwest_res).await;

                RequestOrResponse::Response(res)
            }
        }
        // RequestOrResponse::Response(Response::builder().body(Body::from("foo")).unwrap())
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        res
    }
}

#[tokio::main]
async fn main() {
    setup_logging().unwrap();

    ca::create_ca_if_not_exist();

    let private_key = rustls::PrivateKey(
        pemfile::pkcs8_private_keys(&mut fs::read("cer/ca.key").unwrap().as_slice())
            .expect("Failed to parse private key")
            .remove(0),
    );
    let ca_cert = rustls::Certificate(
        pemfile::certs(&mut fs::read("cer/ca.crt").unwrap().as_slice())
            .expect("Failed to parse CA certificate")
            .remove(0),
    );

    let ca = RcgenAuthority::new(private_key, ca_cert, 1_000)
        .expect("Failed to create Certificate Authority");

    let proxy = Proxy::builder()
        .with_addr(SocketAddr::from(([127, 0, 0, 1], 3000)))
        .with_rustls_client()
        .with_ca(ca)
        .with_http_handler(ProxyHandler)
        .build();

    if let Err(e) = proxy.start(shutdown_signal()).await {
        error!("{}", e);
    }
}

fn setup_logging() -> color_eyre::Result<()> {
    if std::env::var("RUST_LIB_BACKTRACE").is_err() {
        std::env::set_var("RUST_LIB_BACKTRACE", "1");
    }

    if std::env::var("RUST_BACKTRACE").is_err() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    env_logger::init();

    color_eyre::install()?;

    Ok(())
}
