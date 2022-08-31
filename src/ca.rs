use std::{fs, path::Path};

use log::{error, info};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa,
    KeyUsagePurpose,
};

pub fn create_ca_if_not_exist() {
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
