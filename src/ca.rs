use std::{fs, path::Path};

use hudsucker::rustls;
use log::{error, info};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa,
    KeyUsagePurpose,
};
use rustls_pemfile as pemfile;

pub fn acquire_ca() -> (rustls::PrivateKey, rustls::Certificate) {
    create_ca_if_not_exist();

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

    (private_key, ca_cert)
}

fn create_ca_if_not_exist() {
    if !Path::new("cer/ca.crt").exists() || !Path::new("cer/ca.key").exists() {
        let ca = gen_ca();

        if let Err(err) = fs::create_dir_all("cer") {
            error!("Cert folder creation failed: {}", err);
        };

        if let Err(err) = fs::write("cer/ca.crt", ca.cert) {
            error!("Cert file write failed: {}", err);
        }

        if let Err(err) = fs::write("cer/ca.key", ca.key) {
            error!("Private key file write failed: {}", err);
        }

        info!("A certificate has been generated, please ensure it is trusted by the operating system.");
    }
}

struct CAInfo {
    key: String,
    cert: String,
}

fn gen_ca() -> CAInfo {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "hud-proxy");
    dn.push(DnType::OrganizationName, "hud-proxy");
    dn.push(DnType::CountryName, "US");
    dn.push(DnType::StateOrProvinceName, "NY");
    dn.push(DnType::LocalityName, "NYC");

    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        // KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let cert = Certificate::from_params(params).unwrap();
    let cert_crt = cert.serialize_pem().unwrap();
    let key = cert.serialize_private_key_pem();

    CAInfo {
        key,
        cert: cert_crt,
    }
}
