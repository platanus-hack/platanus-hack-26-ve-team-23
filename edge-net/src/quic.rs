//! QUIC between our edges (ADR-0023), adapted from Nepheral's
//! `mesh-network`: mutual TLS 1.3 where each self-standing certificate
//! carries exactly one Ed25519 key, and that key is the peer's identity.
//!
//! One bidirectional stream per request; each message is a 4-byte big-endian
//! length followed by JSON, with the length checked before reading.

use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};

use ed25519_dalek::{pkcs8::EncodePrivateKey, SigningKey};
use quinn::{Connection, Endpoint, IdleTimeout, TransportConfig, VarInt};
use rcgen::{Certificate, CertificateParams, DnType, KeyPair, PKCS_ED25519};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
    DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme,
};
use serde::{de::DeserializeOwned, Serialize};

pub const ALPN: &[u8] = b"hawk/1";
/// Largest message accepted, checked before reading the body.
pub const MAX_FRAME: usize = 4 * 1024 * 1024;
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Server name sent in the handshake; identity is checked by key, not name.
const SERVER_NAME: &str = "hawk-core";

/// A peer's identity: its Ed25519 public key.
pub type PeerId = [u8; 32];

const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Certificate and key for one of our components.
#[derive(Clone)]
pub struct TlsIdentity {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    pub peer_id: PeerId,
}

impl std::fmt::Debug for TlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsIdentity")
            .field("peer_id", &hex::encode(&self.peer_id[..8]))
            .finish_non_exhaustive()
    }
}

impl TlsIdentity {
    /// The certificate for an existing Ed25519 identity key.
    pub fn from_signing_key(key: &SigningKey, common_name: &str) -> Result<Self, String> {
        let pkcs8 = key.to_pkcs8_der().map_err(|e| format!("pkcs8: {e}"))?;
        let key_pair = KeyPair::from_der(pkcs8.as_bytes()).map_err(|e| format!("keypair: {e}"))?;
        let mut params = CertificateParams::default();
        params.alg = &PKCS_ED25519;
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.key_pair = Some(key_pair);
        let cert = Certificate::from_params(params).map_err(|e| format!("certificate: {e}"))?;
        Ok(Self {
            cert_der: cert
                .serialize_der()
                .map_err(|e| format!("certificate: {e}"))?,
            key_der: cert.serialize_private_key_der(),
            peer_id: key.verifying_key().to_bytes(),
        })
    }

    fn cert_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![CertificateDer::from(self.cert_der.clone())]
    }

    fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()))
    }
}

/// The single Ed25519 key a certificate carries, or `None` if it carries
/// none or more than one.
pub fn peer_id_from_cert_der(cert_der: &[u8]) -> Option<PeerId> {
    let mut found: Option<usize> = None;
    let mut start = 0usize;
    while let Some(pos) = cert_der[start..]
        .windows(ED25519_SPKI_PREFIX.len())
        .position(|w| w == ED25519_SPKI_PREFIX)
    {
        if found.is_some() {
            return None;
        }
        found = Some(start + pos);
        start += pos + 1;
    }
    let at = found? + ED25519_SPKI_PREFIX.len();
    let key: [u8; 32] = cert_der.get(at..at + 32)?.try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&key).ok()?;
    Some(key)
}

/// The identity of the peer on an established connection.
pub fn peer_id_of(conn: &Connection) -> Option<PeerId> {
    let identity = conn.peer_identity()?;
    let certs = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    peer_id_from_cert_der(certs.first()?.as_ref())
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

#[derive(Debug)]
struct PeerCertVerifier {
    expected: Option<PeerId>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl PeerCertVerifier {
    fn check(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> Result<(), TlsError> {
        if !intermediates.is_empty() {
            return Err(TlsError::General("certificates are self-standing".into()));
        }
        let id = peer_id_from_cert_der(end_entity.as_ref()).ok_or_else(|| {
            TlsError::General("certificate does not carry one Ed25519 key".into())
        })?;
        match self.expected {
            Some(expected) if expected != id => Err(TlsError::General(format!(
                "peer presented {} but {} was expected",
                hex::encode(&id[..8]),
                hex::encode(&expected[..8])
            ))),
            _ => Ok(()),
        }
    }

    fn check_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        if dss.scheme != SignatureScheme::ED25519 {
            return Err(TlsError::General(
                "only Ed25519 handshakes are accepted".into(),
            ));
        }
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }
}

impl ServerCertVerifier for PeerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        self.check(end_entity, intermediates)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 is not accepted".into()))
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.check_signature(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

impl ClientCertVerifier for PeerCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        self.check(end_entity, intermediates)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 is not accepted".into()))
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.check_signature(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

fn transport() -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.max_concurrent_bidi_streams(VarInt::from(64u32))
        .max_concurrent_uni_streams(VarInt::from(0u32))
        .keep_alive_interval(Some(Duration::from_secs(10)))
        .max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(30_000))));
    Arc::new(t)
}

/// A QUIC server endpoint that requires every client to present an identity.
pub fn server(identity: &TlsIdentity, bind: SocketAddr) -> Result<Endpoint, String> {
    let provider = provider();
    let verifier = Arc::new(PeerCertVerifier {
        expected: None,
        algorithms: provider.signature_verification_algorithms,
    });
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(identity.cert_chain(), identity.private_key())
        .map_err(|e| e.to_string())?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|e| e.to_string())?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(transport());
    Endpoint::server(config, bind).map_err(|e| e.to_string())
}

/// A client: connects with its identity and accepts only `expected` when set.
#[derive(Debug, Clone)]
pub struct Client {
    endpoint: Endpoint,
    identity: TlsIdentity,
}

impl Client {
    pub fn new(identity: TlsIdentity) -> Result<Self, String> {
        let bind: SocketAddr = "0.0.0.0:0".parse().map_err(|e| format!("{e}"))?;
        let endpoint = Endpoint::client(bind).map_err(|e| e.to_string())?;
        Ok(Self { endpoint, identity })
    }

    pub fn peer_id(&self) -> PeerId {
        self.identity.peer_id
    }

    /// Connects and returns the connection and the peer's identity.
    pub async fn connect(
        &self,
        addr: SocketAddr,
        expected: Option<PeerId>,
    ) -> Result<(Connection, PeerId), String> {
        let provider = provider();
        let verifier = Arc::new(PeerCertVerifier {
            expected,
            algorithms: provider.signature_verification_algorithms,
        });
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| e.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(self.identity.cert_chain(), self.identity.private_key())
            .map_err(|e| e.to_string())?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|e| e.to_string())?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        config.transport_config(transport());

        let connecting = self
            .endpoint
            .connect_with(config, addr, SERVER_NAME)
            .map_err(|e| format!("connect: {e}"))?;
        let conn = tokio::time::timeout(CONNECT_TIMEOUT, connecting)
            .await
            .map_err(|_| format!("timed out connecting to {addr}"))?
            .map_err(|e| format!("connection failed: {e}"))?;
        let id = peer_id_of(&conn).ok_or_else(|| {
            conn.close(0u32.into(), b"no identity");
            "peer presented no usable identity".to_owned()
        })?;
        Ok((conn, id))
    }
}

fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if body.len() > MAX_FRAME {
        return Err("message too large".into());
    }
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

async fn write_frame(send: &mut quinn::SendStream, frame: &[u8]) -> Result<(), String> {
    send.write_all(frame).await.map_err(|e| e.to_string())
}

async fn read_frame<T: DeserializeOwned>(recv: &mut quinn::RecvStream) -> Result<T, String> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await.map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err("message too large".into());
    }
    let mut bytes = vec![0u8; len];
    recv.read_exact(&mut bytes)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| format!("malformed message: {e}"))
}

/// Sends one request on a new stream and waits for the answer, bounded by
/// `timeout`.
pub async fn request<Q: Serialize, R: DeserializeOwned>(
    conn: &Connection,
    req: &Q,
    timeout: Duration,
) -> Result<R, String> {
    let call = async {
        let frame = encode_frame(req)?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
        write_frame(&mut send, &frame).await?;
        send.finish().map_err(|e| e.to_string())?;
        read_frame(&mut recv).await
    };
    tokio::time::timeout(timeout, call)
        .await
        .map_err(|_| "request timed out".to_owned())?
}

/// Answers the requests the peer opens on `conn` until it closes. Used by the
/// server for every client, and by a client to answer requests its server
/// opens towards it (the Core asking a host daemon to identify itself).
pub async fn serve_connection<Q, R, H, F>(conn: Connection, peer: PeerId, handler: H)
where
    Q: DeserializeOwned + Send + 'static,
    R: Serialize + Send + 'static,
    H: Fn(PeerId, SocketAddr, Q) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = R> + Send + 'static,
{
    let addr = conn.remote_address();
    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        let handler = handler.clone();
        tokio::spawn(async move {
            match read_frame::<Q>(&mut recv).await {
                Ok(req) => {
                    let resp = handler(peer, addr, req).await;
                    let Ok(frame) = encode_frame(&resp) else {
                        let _ = send.reset(2u32.into());
                        return;
                    };
                    if write_frame(&mut send, &frame).await.is_ok() {
                        let _ = send.finish();
                    }
                }
                Err(err) => {
                    tracing::debug!(%err, %addr, "bad request");
                    let _ = send.reset(1u32.into());
                }
            }
        });
    }
}

/// Accepts connections forever. `on_connect` sees every authenticated
/// connection (so the server can open streams towards that peer later);
/// each request stream is handled on its own task with the peer's identity
/// and address. A malformed or oversized request closes that stream only.
pub async fn serve_with<Q, R, H, F, C>(endpoint: Endpoint, on_connect: C, handler: H)
where
    Q: DeserializeOwned + Send + 'static,
    R: Serialize + Send + 'static,
    H: Fn(PeerId, SocketAddr, Q) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = R> + Send + 'static,
    C: Fn(PeerId, Connection) + Clone + Send + Sync + 'static,
{
    while let Some(incoming) = endpoint.accept().await {
        let handler = handler.clone();
        let on_connect = on_connect.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(conn) => conn,
                Err(err) => {
                    tracing::debug!(%err, "handshake failed");
                    return;
                }
            };
            let Some(peer) = peer_id_of(&conn) else {
                conn.close(0u32.into(), b"no identity");
                return;
            };
            on_connect(peer, conn.clone());
            serve_connection(conn, peer, handler).await;
        });
    }
}

/// `serve_with` without a connection hook.
pub async fn serve<Q, R, H, F>(endpoint: Endpoint, handler: H)
where
    Q: DeserializeOwned + Send + 'static,
    R: Serialize + Send + 'static,
    H: Fn(PeerId, SocketAddr, Q) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = R> + Send + 'static,
{
    serve_with(endpoint, |_peer, _conn| {}, handler).await;
}

/// A short, human-comparable fingerprint of an identity: the first 8 bytes
/// of SHA-256 over the key, in four groups (`a1b2-c3d4-e5f6-0718`).
pub fn fingerprint(id: &PeerId) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::new()
        .chain_update(b"hawk.fingerprint.v1")
        .chain_update(id)
        .finalize();
    hex::encode(&digest[..8])
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn identity(name: &str) -> TlsIdentity {
        TlsIdentity::from_signing_key(&SigningKey::generate(&mut OsRng), name).unwrap()
    }

    #[test]
    fn the_identity_is_the_certificate_key() {
        let id = identity("t");
        assert_eq!(peer_id_from_cert_der(&id.cert_der), Some(id.peer_id));
        let mut doubled = id.cert_der.clone();
        doubled.extend_from_slice(&ED25519_SPKI_PREFIX);
        doubled.extend_from_slice(&[1u8; 32]);
        assert_eq!(peer_id_from_cert_der(&doubled), None);
    }

    async fn echo_server() -> (SocketAddr, PeerId) {
        let id = identity("server");
        let endpoint = server(&id, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        tokio::spawn(serve(
            endpoint,
            |peer: PeerId, _addr, req: String| async move {
                format!("{}:{req}", hex::encode(&peer[..2]))
            },
        ));
        (addr, id.peer_id)
    }

    #[tokio::test]
    async fn request_round_trip_with_both_identities() {
        let (addr, server_id) = echo_server().await;
        let client = Client::new(identity("client")).unwrap();
        let (conn, seen) = client.connect(addr, Some(server_id)).await.unwrap();
        assert_eq!(seen, server_id);
        let answer: String = request(&conn, &"hi".to_owned(), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(
            answer,
            format!("{}:hi", hex::encode(&client.peer_id()[..2]))
        );
    }

    #[tokio::test]
    async fn a_different_server_identity_is_refused() {
        let (addr, _) = echo_server().await;
        let client = Client::new(identity("client")).unwrap();
        assert!(client.connect(addr, Some([7u8; 32])).await.is_err());
    }

    #[test]
    fn fingerprints_are_grouped_and_key_dependent() {
        let a = fingerprint(&[1u8; 32]);
        assert_eq!(a.len(), 19);
        assert_eq!(a.matches('-').count(), 3);
        assert_ne!(a, fingerprint(&[2u8; 32]));
    }
}
