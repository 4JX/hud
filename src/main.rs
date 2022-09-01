use hudsucker::certificate_authority::RcgenAuthority;
use log::info;

use crate::proxy::ProxyWrapper;

mod auth;
mod ca;
mod convert;
mod proxy;
mod response;
mod route;
mod storage;

const RUST_LOG: &str = "RUST_LOG";

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    setup_logging()?;

    info!("Starting up proxy");

    let (private_key, ca_cert) = ca::acquire_ca();

    let ca = RcgenAuthority::new(private_key, ca_cert, 1_000)
        .expect("Failed to create Certificate Authority");

    ProxyWrapper::new().start(ca).await;

    Ok(())
}

fn setup_logging() -> color_eyre::Result<()> {
    // if std::env::var("RUST_LIB_BACKTRACE").is_err() {
    //     std::env::set_var("RUST_LIB_BACKTRACE", "1");
    // }

    // if std::env::var("RUST_BACKTRACE").is_err() {
    //     std::env::set_var("RUST_BACKTRACE", "1");
    // }

    if std::env::var(RUST_LOG).is_err() {
        std::env::set_var(RUST_LOG, "error,hud=info");
    }

    env_logger::init();

    color_eyre::install()?;

    Ok(())
}
