use crate::control::message::{
    ControlMessage, CryptoAlgorithms, DecryptedMessage, PeerInfoMessage,
};
use crate::key::device::DevicePublicKey;
use crate::key::message::MessageCipher;
use crate::key::sas::Sas;
use crate::state::ServiceState;
use crate::ServiceMessage;
use async_std::net::TcpStream;
use async_tungstenite::{tungstenite, WebSocketStream};
use futures::stream::FusedStream;
use futures::{SinkExt, StreamExt};
use rand::RngCore;
use std::collections::HashSet;
use std::net::SocketAddr;
use x25519_dalek::SharedSecret;

const APP_ID: &'static str = "app.drey.Warp.zeroconf0";

#[derive(Debug, thiserror::Error)]
#[must_use]
pub enum ConnectionError {
    #[error("I/O error")]
    IO {
        #[from]
        source: std::io::Error,
    },
    #[error("serde_json error: {}", source)]
    Serde {
        #[from]
        source: serde_json::Error,
    },
    #[error("Error parsing JSON message: {:?}", _0)]
    JsonParse(String),
    #[error("Received unexpected message type: {:?}", _0)]
    UnexpectedType(tungstenite::Message),
    #[error("WebSocket error: {}", source)]
    WebSocket {
        #[from]
        source: tungstenite::Error,
    },
    #[error("WebSocket closed")]
    Closed(Option<tungstenite::protocol::CloseFrame<'static>>),
    #[error("Peer failed to verify our connection")]
    VerificationFailed,
    #[error("An unexpected state has occurred")]
    InvalidState,
    #[error("Peer already exists, not adding twice")]
    PeerExists,
    #[error("A cryptographic constraint was not held")]
    CryptoError,
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub socket_addrs: HashSet<SocketAddr>,
    pub public_key: Vec<u8>,
    pub authenticated: bool,

    pub message: PeerInfoMessage,
}

impl PeerInfo {
    pub fn with_key_and_message(public_key: Vec<u8>, message: PeerInfoMessage) -> Self {
        Self {
            socket_addrs: Default::default(),
            public_key,
            authenticated: false,
            message,
        }
    }

    pub fn update_message(&mut self, message: PeerInfoMessage) {
        self.message = message;
    }
}

pub struct ControlServer {
    listener: async_std::net::TcpListener,
    state: ServiceState,
}

impl ControlServer {
    pub async fn run(state: ServiceState, port: u16) -> Result<Self, std::io::Error> {
        let addrs: [async_std::net::SocketAddr; 2] = [
            format!("[::]:{}", port).parse().unwrap(),
            format!("0.0.0.0:{}", port).parse().unwrap(),
        ];

        let listener = async_std::net::TcpListener::bind(&addrs[..]).await?;
        Ok(Self { listener, state })
    }

    pub fn port(&self) -> u16 {
        self.listener.local_addr().unwrap().port()
    }

    pub fn state(&self) -> ServiceState {
        self.state.clone()
    }

    pub async fn wait_for_connection(&mut self) {
        while let Some(stream) = self.listener.incoming().next().await {
            println!("Connection!");
            let Ok(stream) = stream else {
                return;
            };

            let state = self.state.clone();
            let Ok(peer_addr) = stream.peer_addr() else {
                println!("Peer doesn't have an address");
                continue;
            };

            async_std::task::spawn(async move {
                let mut ws = match async_tungstenite::accept_async(stream).await {
                    Ok(ws) => ws,
                    Err(err) => {
                        println!("Websocket error: {}", err);
                        return;
                    }
                };

                let mut connection = ControlServerConnection::new(&mut ws, state, peer_addr);
                if let Err(err) = connection.handle_connection().await {
                    println!("Connection error: {}", err);
                }

                if !ws.is_terminated() {
                    println!("Closing websocket");
                    match ws.close(None).await {
                        Ok(()) => {}
                        Err(err) => {
                            if !matches!(err, tungstenite::Error::ConnectionClosed) {
                                println!("Websocket connection error: {}", err);
                            }
                        }
                    }
                }
            });
        }
    }

    pub async fn connect_to_peer(state: ServiceState, socket_addr: SocketAddr) {
        async_std::task::spawn(async move {
            println!("Connecting to {}", socket_addr);
            let stream = TcpStream::connect(socket_addr).await.unwrap();
            println!("Connected");
            let server_url =
                url::Url::parse(&format!("ws://{}/v1", socket_addr.to_string())).unwrap();
            let (mut ws, response) = async_tungstenite::client_async(server_url, stream)
                .await
                .unwrap();
            let connection = ControlServerConnection::new(&mut ws, state, socket_addr);
            connection.client_connection().await.unwrap();
        });
    }
}

// This Mutex ensures that handshakes don't occur at the same time
// If they did we could have more than one key per peer which is undersirable
static HANDSHAKE_LOCK: async_std::sync::Mutex<()> = async_std::sync::Mutex::new(());

struct ControlServerConnection<'a, T> {
    websocket: &'a mut WebSocketStream<T>,
    state: ServiceState,
    peer_id: Option<String>,
    shared_secret: Option<SharedSecret>,
    cipher: Option<MessageCipher>,
    challenge: Option<Vec<u8>>,
    peer_key: Option<Vec<u8>>,
    authenticated_peer: bool,
    peer_addr: SocketAddr,
}

impl<'a, T> ControlServerConnection<'a, T>
where
    T: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    pub fn new(
        websocket: &'a mut WebSocketStream<T>,
        state: ServiceState,
        peer_addr: SocketAddr,
    ) -> Self {
        Self {
            websocket,
            state,
            peer_id: None,
            cipher: None,
            challenge: None,
            shared_secret: None,
            peer_key: None,
            authenticated_peer: false,
            peer_addr,
        }
    }

    pub async fn send_msg(&mut self, msg: &ControlMessage) -> Result<(), tungstenite::Error> {
        let json = serde_json::to_string(msg).unwrap();
        println!("Send: {}", json);
        self.websocket.send(json.into()).await
    }

    pub async fn send_encrypted_msg(
        &mut self,
        msg: DecryptedMessage,
    ) -> Result<(), ConnectionError> {
        let Some(cipher) = &mut self.cipher else {
            return Err(ConnectionError::CryptoError);
        };

        let enc_msg = cipher.encrypt_message(&msg)?;
        Ok(self
            .send_msg(&ControlMessage::EncryptedMessage { data: enc_msg })
            .await?)
    }

    async fn receive_msg(&mut self) -> Result<ControlMessage, ConnectionError> {
        while let Some(Ok(msg)) = self.websocket.next().await {
            return match msg {
                tungstenite::Message::Text(msg_txt) => {
                    println!("Receive: {}", msg_txt);
                    let client_msg = serde_json::from_str(&msg_txt);
                    client_msg.map_err(|_err| ConnectionError::JsonParse(msg_txt))
                }
                tungstenite::Message::Close(frame) => Err(ConnectionError::Closed(frame)),
                tungstenite::Message::Ping(data) => {
                    self.websocket
                        .send(tungstenite::Message::Pong(data))
                        .await?;

                    // Wait for a new message, this one isn't interesting
                    continue;
                }
                msg => Err(ConnectionError::UnexpectedType(msg)),
            };
        }

        Err(ConnectionError::Closed(None))
    }

    pub async fn receive_encrypted_msg(&mut self) -> Result<DecryptedMessage, ConnectionError> {
        let msg = self.receive_msg().await?;
        let Some(cipher) = &mut self.cipher else {
            return Err(ConnectionError::CryptoError);
        };

        let ControlMessage::EncryptedMessage { data: encrypted } = msg else {
            return Err(ConnectionError::CryptoError);
        };

        cipher.decrypt_message(&encrypted)
    }

    async fn alloc_code(&mut self) -> String {
        "23-abc-def".to_string()
    }

    /// Returns Ok(false) if the connection was terminated
    async fn handle_decrypted_message(
        &mut self,
        msg: &DecryptedMessage,
    ) -> Result<(), ConnectionError> {
        match msg {
            DecryptedMessage::RequestInfo => {
                let my_info = self.state.read().my_info.clone();
                self.send_encrypted_msg(DecryptedMessage::Info(my_info))
                    .await?;
            }
            DecryptedMessage::Info(peer_info) => {
                println!("Received peer info: {:?}", peer_info);
                let peer_addr = self.peer_addr.clone();
                let peer_id = peer_info.service_uuid.clone();
                self.peer_id = Some(peer_id.clone());
                let Some(peer_key) = &self.peer_key else {
                    return Err(ConnectionError::CryptoError);
                };

                let peer_info = {
                    // This block is needed to scope the lock for the await below
                    let mut lock = self.state.write();
                    if !lock.peers.contains_key(&peer_info.service_uuid) {
                        if peer_info.service_uuid == lock.my_info.service_uuid {
                            println!("Accidentally connected to myself");
                            return Err(ConnectionError::PeerExists);
                        }

                        let mut peer =
                            PeerInfo::with_key_and_message(peer_key.clone(), peer_info.clone());
                        peer.socket_addrs.insert(peer_addr);
                        lock.peers.insert(peer_id.clone(), peer.clone());
                        peer_info.clone()
                    } else {
                        println!("Peer already exists, checking key validity");
                        let Some(mut peer) = lock.peers
                            .get_mut(&peer_info.service_uuid) else {
                            return Err(ConnectionError::InvalidState);
                        };

                        if peer.authenticated && !self.authenticated_peer {
                            // Don't trust unauthenticated peer info if we already got successful auth
                            // This means the peer uses different keys which can't be right
                            return Err(ConnectionError::CryptoError);
                        }

                        // Update the info and ip addresses
                        peer.update_message(peer_info.clone());
                        peer.socket_addrs.insert(peer_addr);
                        peer_info.clone()
                    }
                };

                // Inform the service about peer update
                let sender = self.state.read().service_sender.clone();
                sender
                    .send(ServiceMessage::PeerAddedUpdated { peer_id, peer_info })
                    .await
                    .map_err(|_| ConnectionError::InvalidState)?;
            }
            DecryptedMessage::AllocWormhole => {
                if !self.authenticated_peer {
                    self.send_encrypted_msg(DecryptedMessage::AuthenticationFailed)
                        .await?;
                } else {
                    let port = self.state.read().rendezvous_port;
                    let code = self.alloc_code().await;
                    self.send_encrypted_msg(DecryptedMessage::Wormhole { port, code })
                        .await?;
                }
            }
            DecryptedMessage::Wormhole { port, code } => {
                if !self.authenticated_peer {
                    self.send_encrypted_msg(DecryptedMessage::AuthenticationFailed)
                        .await?;
                } else {
                    println!(
                        "Allocated wormhole: {}, mailbox server port: {}",
                        code, port
                    );
                }
            }
            DecryptedMessage::AuthenticationFailed => {
                println!("Invalid verification message received from peer.");
                return Err(ConnectionError::VerificationFailed);
            }
            DecryptedMessage::Remove => {
                // Remove the peer from all discovery lists
                if let Some(peer_id) = &self.peer_id {
                    let old_id = peer_id.clone();
                    self.state.write().peers.remove(peer_id);
                    self.peer_id = None;

                    // Inform the service about peer update
                    let sender = self.state.read().service_sender.clone();
                    sender
                        .send(ServiceMessage::PeerRemoved { peer_id: old_id })
                        .await
                        .map_err(|_| ConnectionError::InvalidState)?;

                    return Err(ConnectionError::Closed(None));
                }
            }
            msg => {
                println!("unexpected message received");
                return Err(ConnectionError::CryptoError);
            }
        }

        Ok(())
    }

    pub async fn handle_connection(&mut self) -> Result<(), ConnectionError> {
        self.handshake(false).await?;

        while !self.websocket.is_terminated() {
            let msg = self.receive_encrypted_msg().await?;
            self.handle_decrypted_message(&msg).await?;
        }

        // TODO how to clean up client data?
        /*if let Some(peer_id) = &self.peer_id {
            // Remove the peer data because the connection got lost
            // This way the peers list semi-reliably only contains a list of online peers
            self.state.write().peers.remove(peer_id);
        }*/

        Ok(())
    }

    pub async fn authenticate_peer(&mut self, is_client: bool) -> Result<(), ConnectionError> {
        // Authentication stage: Here we compare the key to our authorized keys and decide whether
        // to do manual user verification
        let my_pubkey = self.state.read().device_key.public_key().to_vec();
        let Some(their_pubkey) = &self.peer_key.clone() else {
            return Err(ConnectionError::CryptoError);
        };

        if self.state.read().authorized_keys.contains(their_pubkey) {
            let msg = self.receive_encrypted_msg().await?;
            match msg {
                DecryptedMessage::UserAuthenticate => {
                    // Fall through and go through user authentication flow
                }
                DecryptedMessage::AuthenticationSuccess => {
                    // We agree that we don't need verification
                    self.authenticated_peer = true;
                }
                DecryptedMessage::AuthenticationFailed => {
                    println!("Authentication failed");
                    return Err(ConnectionError::CryptoError);
                }
                _ => {
                    println!("Expected authentication message");
                    return Err(ConnectionError::CryptoError);
                }
            }

            self.authenticated_peer = true;
        }

        if !self.authenticated_peer {
            // We need to use verification
            println!("User authentication");
            self.send_encrypted_msg(DecryptedMessage::UserAuthenticate)
                .await?;

            let Some(shared_secret) = &self.shared_secret else {
                return Err(ConnectionError::CryptoError);
            };

            // Calculate SAS
            let sas = Sas::new_hkdf_sha265(
                self.shared_secret.as_ref().unwrap().as_bytes(),
                &my_pubkey,
                their_pubkey,
                is_client,
            );

            println!(
                "Please verify that these emoji match (y/n): {}",
                sas.get_emoji_string(6).1
            );
            let mut line_buf = String::new();
            let stdin = async_std::io::stdin();
            let mut verified_emoji = false;

            while !verified_emoji {
                stdin.read_line(&mut line_buf).await.unwrap();

                if line_buf.to_lowercase() == "y" {
                    self.send_encrypted_msg(DecryptedMessage::AuthenticationSuccess)
                        .await?;
                    verified_emoji = true;
                } else if line_buf.to_lowercase() == "n" {
                    self.send_encrypted_msg(DecryptedMessage::AuthenticationFailed)
                        .await?;
                    return Err(ConnectionError::CryptoError);
                }

                line_buf.clear();
            }

            let msg = self.receive_encrypted_msg().await?;
            match msg {
                DecryptedMessage::AuthenticationSuccess => {
                    println!("Authentication success!");
                    self.authenticated_peer = true;
                }
                DecryptedMessage::AuthenticationFailed => {
                    println!("Authentication failed");
                    return Err(ConnectionError::CryptoError);
                }
                _ => {
                    println!("Expected authentication message");
                    return Err(ConnectionError::CryptoError);
                }
            }
        }

        Ok(())
    }

    pub async fn handshake(&mut self, is_client: bool) -> Result<(), ConnectionError> {
        println!("Handshake");
        // Keep this locked for the whole function
        let handshake_lock = HANDSHAKE_LOCK.lock().await;

        // Now that we have the lock we can make some assumptions:
        // 1. No handshake will occur at the same time
        // 2. As only the handshake sets the shared secret, this will be in a stable state:
        //    We either have one, or we don't and need to do a key exchange

        // Find out peer public key. Anyone could claim they are a specific peer, but we will verify
        // this later after key exchange with the ed25519 certificate

        println!("Key exchange");

        // Key exchange
        let my_ephemeral_secret = x25519_dalek::EphemeralSecret::new(rand::rngs::OsRng);
        let my_ephemeral_pubkey = x25519_dalek::PublicKey::from(&my_ephemeral_secret);

        self.send_msg(&ControlMessage::KeyExchangeX25519 {
            algorithms: CryptoAlgorithms::Ed25519ChaCha20Poly1305,
            public_key: my_ephemeral_pubkey.as_bytes().to_vec(),
        })
        .await?;

        let ControlMessage::KeyExchangeX25519 {
            algorithms, public_key: their_data
        } = self.receive_msg().await? else {
            return Err(ConnectionError::CryptoError);
        };

        if algorithms != CryptoAlgorithms::Ed25519ChaCha20Poly1305 {
            return Err(ConnectionError::CryptoError);
        }

        let their_data_32: [u8; 32] = their_data
            .try_into()
            .or(Err(ConnectionError::CryptoError))?;

        // We use the secret to generate our cipher
        let their_ephemeral_pubkey = x25519_dalek::PublicKey::from(their_data_32);
        let shared_secret = my_ephemeral_secret.diffie_hellman(&their_ephemeral_pubkey);
        let cipher = MessageCipher::from_secret(&shared_secret.to_bytes())
            .ok_or(ConnectionError::CryptoError)?;
        self.shared_secret = Some(shared_secret);
        self.cipher = Some(cipher);

        // Now we have a cipher, let's continue encrypted
        let mut challenge = vec![64u8; 64];
        rand::rngs::OsRng::default().fill_bytes(&mut challenge);
        self.challenge = Some(challenge.clone());

        self.send_encrypted_msg(DecryptedMessage::KeyVerificationEd25519 { challenge })
            .await?;

        let mut other_verified_key = false;
        let mut verified_key = false;
        while !verified_key || !other_verified_key {
            let msg = self.receive_encrypted_msg().await?;
            match msg {
                DecryptedMessage::KeyVerificationEd25519 { challenge } => {
                    if challenge.len() < 64 {
                        return Err(ConnectionError::CryptoError);
                    }

                    // We need to sign the challenge
                    let (public_key, signature) = {
                        let device_key = &mut self.state.write().device_key;
                        let public_key = device_key.public_key().to_vec();

                        // concatenate public key and challenge
                        let mut data = challenge.clone();
                        data.extend_from_slice(&public_key);
                        let signature = device_key.sign(&data);
                        (public_key, signature)
                    };

                    self.send_encrypted_msg(DecryptedMessage::KeyVerificationResponseEd25519 {
                        public_key,
                        signature,
                    })
                    .await?;

                    other_verified_key = true;
                }
                DecryptedMessage::KeyVerificationResponseEd25519 {
                    public_key,
                    signature,
                } => {
                    let Some(challenge) = &self.challenge else {
                        return Err(ConnectionError::CryptoError);
                    };

                    if challenge.is_empty() || public_key.is_empty() || signature.is_empty() {
                        return Err(ConnectionError::CryptoError);
                    }

                    println!("Challenge: {:?}", challenge);

                    // Check if the signature matches the challenge + key
                    let mut data = challenge.clone();
                    data.extend_from_slice(&public_key);
                    let key = DevicePublicKey::from_data(&public_key)
                        .ok_or(ConnectionError::CryptoError)?;
                    if !key.verify(&data, &signature) {
                        return Err(ConnectionError::CryptoError);
                    } else {
                        verified_key = true;
                        self.peer_key = Some(public_key);
                    }

                    self.challenge = None;
                }
                msg => {
                    println!("Unexpected message, expected key verification");
                    return Err(ConnectionError::CryptoError);
                }
            }
        }

        println!("Verified the public key of peer");

        // Make sure the handshake lock exists until the end of this function.
        // drop consumes the lock, therefore it must exist up until this point.
        drop(handshake_lock);
        Ok(())
    }

    pub async fn client_connection(mut self) -> Result<(), ConnectionError> {
        println!("Client connection");
        self.handshake(true).await?;

        self.send_encrypted_msg(DecryptedMessage::RequestInfo)
            .await?;
        // This will err if peer already exists
        let msg = self.receive_encrypted_msg().await?;
        self.handle_decrypted_message(&msg).await?;

        println!("Verifying peer connection");
        self.send_encrypted_msg(DecryptedMessage::UserAuthenticate)
            .await?;
        // This will err if not verified
        let msg = self.receive_encrypted_msg().await?;
        self.handle_decrypted_message(&msg).await?;

        println!("Allocating wormhole");
        self.send_encrypted_msg(DecryptedMessage::AllocWormhole)
            .await?;
        let msg = self.receive_encrypted_msg().await?;
        self.handle_decrypted_message(&msg).await?;
        self.websocket.close(None).await?;

        Ok(())
    }
}
