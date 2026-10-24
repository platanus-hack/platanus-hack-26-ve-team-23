//! HTTPS client for routers. Routers in a lab or a small office usually
//! present a self-signed certificate, so instead of a public CA the client
//! pins the SHA-256 fingerprint of the router's certificate. Without a pin
//! it refuses HTTPS rather than accepting any certificate.

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::Full;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use sha2::{Digest, Sha256};

pub type HttpsClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Accepts exactly one certificate, identified by its SHA-256 fingerprint.
#[derive(Debug)]
struct PinnedCert {
    fingerprint: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if actual == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "certificate fingerprint {} does not match the pinned one",
                hex::encode(actual)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Parses a fingerprint written as hex, with or without `:` separators.
pub fn parse_fingerprint(text: &str) -> Option<[u8; 32]> {
    let clean: String = text.chars().filter(|c| *c != ':').collect();
    hex::decode(clean).ok()?.try_into().ok()
}

/// A client that speaks HTTPS only to a server whose certificate matches
/// `fingerprint`, and plain HTTP when the URL says so.
pub fn pinned_client(fingerprint: [u8; 32], connect_timeout: Duration) -> HttpsClient {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map(|b| {
            b.dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedCert {
                    fingerprint,
                    provider,
                }))
                .with_no_client_auth()
        });
    let config = match config {
        Ok(config) => config,
        // The ring provider always supports the default versions; this is
        // unreachable in practice, and an empty config fails every handshake.
        Err(_) => rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
    };
    let mut http = HttpConnector::new();
    http.set_connect_timeout(Some(connect_timeout));
    http.enforce_http(false);
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);
    Client::builder(hyper_util::rt::TokioExecutor::new()).build(connector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_parse_with_or_without_colons() {
        let hex64 = "ab".repeat(32);
        let colons = vec!["ab"; 32].join(":");
        assert_eq!(parse_fingerprint(&hex64), Some([0xab; 32]));
        assert_eq!(parse_fingerprint(&colons), Some([0xab; 32]));
        assert_eq!(parse_fingerprint("abcd"), None);
    }
}
