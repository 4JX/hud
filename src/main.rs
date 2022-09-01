use std::fs;

use crate::proxy::ProxyWrapper;
use hudsucker::{certificate_authority::RcgenAuthority, rustls};
use rustls_pemfile as pemfile;

mod auth;
mod ca;
mod convert;
mod proxy;
mod response;
mod route;
mod storage;

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

    ProxyWrapper::new().start(ca).await;
}

fn setup_logging() -> color_eyre::Result<()> {
    // if std::env::var("RUST_LIB_BACKTRACE").is_err() {
    //     std::env::set_var("RUST_LIB_BACKTRACE", "1");
    // }

    // if std::env::var("RUST_BACKTRACE").is_err() {
    //     std::env::set_var("RUST_BACKTRACE", "1");
    // }

    env_logger::init();

    color_eyre::install()?;

    Ok(())
}
