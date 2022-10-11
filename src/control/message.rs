use serde_derive::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    #[serde(skip)]
    pub socket_addrs: HashSet<SocketAddr>,
    pub machine_name: String,
    pub service_uuid: String,
    pub user_name: Option<String>,
    pub user_picture: Option<Vec<u8>>,
}

impl PeerInfo {
    pub fn new(
        machine_name: String,
        service_uuid: String,
        user_name: Option<String>,
        user_picture: Option<Vec<u8>>,
    ) -> Self {
        Self {
            socket_addrs: HashSet::new(),
            machine_name,
            service_uuid,
            user_name,
            user_picture,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum DecryptedMessage {
    KeyVerificationEd25519 {
        challenge: Vec<u8>,
    },
    KeyVerificationResponseEd25519 {
        public_key: Vec<u8>,
        signature: Vec<u8>,
    },
    RequestInfo,
    Info(PeerInfo),
    AllocWormhole,
    VerificationFailed,
    Wormhole {
        port: u16,
        code: String,
    },
    Remove,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub(crate) nonce: Vec<u8>,
    pub(crate) data: Vec<u8>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub enum CryptoAlgorithms {
    Ed25519ChaCha20Poly1305,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "type")]
pub(crate) enum ControlMessage {
    KeyExchangeX25519 {
        algorithms: CryptoAlgorithms,
        public_key: Vec<u8>,
    },
    EncryptedMessage {
        data: EncryptedMessage,
    },
}
