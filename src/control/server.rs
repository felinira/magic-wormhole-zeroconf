use crate::control::message::{
    ControlMessage, CryptoAlgorithms, DecryptedMessage, PeerInfoMessage,
};
use crate::key::device::DevicePublicKey;
use crate::key::message::MessageCipher;
use crate::key::sas::Sas;
use crate::service::ServiceMessage;
use crate::state::ServiceState;
use async_std::net::TcpStream;
use async_tungstenite::{tungstenite, WebSocketStream};
use futures::stream::FusedStream;
use futures::{SinkExt, StreamExt};
use hkdf::Hkdf;
use rand::{Rng, RngCore};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

const APP_ID: &str = "app.drey.Warp.zeroconf0";

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

pub enum ControlServerMessage {
    CompareEmoji {
        peer_id: String,
        emoji: String,
        verbose_emoji: String,
        result_fn: Box<dyn FnOnce(bool) + Send>,
    },
    CompareEmojiPeerResult {
        peer_id: String,
        result: bool,
    },
    RequestInitiateTransfer {
        peer_id: String,
        result_fn: Box<dyn FnOnce(bool) + Send>,
    },
    InitiateTransferPeerResult {
        peer_id: String,
        result: bool,
    },
    AllocatedWormhole {
        send: bool,
        peer_id: String,
        mailbox_addr: SocketAddr,
        code: String,
    },
    PeerRemoved {
        peer_id: String,
    },
}

#[derive(Clone)]
pub struct Peer {
    pub socket_addrs: HashSet<SocketAddr>,
    pub public_key: Vec<u8>,
    pub cipher: MessageCipher,
    pub sas_secret: [u8; 32],
    pub authenticated: bool,

    pub message: Option<PeerInfoMessage>,
}

impl Peer {
    pub fn with_key(public_key: Vec<u8>, sas_secret: [u8; 32], cipher: MessageCipher) -> Self {
        Self {
            socket_addrs: Default::default(),
            public_key,
            cipher,
            sas_secret,
            authenticated: false,
            message: None,
        }
    }

    pub fn update_message(&mut self, message: PeerInfoMessage) {
        self.message = Some(message);
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

    pub async fn stop(self) {
        // This is the same as drop(), but might be augmented for later expansion
    }

    pub fn port(&self) -> u16 {
        self.listener.local_addr().unwrap().port()
    }

    pub fn state(&self) -> ServiceState {
        self.state.clone()
    }

    pub async fn wait_for_connection(
        &mut self,
        service_sender: async_channel::Sender<ControlServerMessage>,
    ) {
        while let Some(stream) = self.listener.incoming().next().await {
            log::debug!("Connection!");
            let Ok(stream) = stream else {
                return;
            };

            let state = self.state.clone();
            let Ok(peer_addr) = stream.peer_addr() else {
                log::warn!("Peer doesn't have an address");
                continue;
            };

            let service_sender_clone = service_sender.clone();

            async_std::task::spawn(async move {
                let mut ws = match async_tungstenite::accept_async(stream).await {
                    Ok(ws) => ws,
                    Err(err) => {
                        log::error!("Websocket error: {}", err);
                        return;
                    }
                };

                let mut connection = ControlServerConnection::new(
                    &mut ws,
                    service_sender_clone,
                    false,
                    state,
                    peer_addr.ip(),
                );
                if let Err(err) = connection.handle_connection().await {
                    match err {
                        ConnectionError::Closed(close_frame) => {
                            log::debug!("Websocket closed");
                            let _ = ws.close(close_frame).await;
                        }
                        err => {
                            log::error!("Connection error: {}", err);
                        }
                    }
                }

                if !ws.is_terminated() {
                    log::debug!("Closing websocket");
                    match ws.close(None).await {
                        Ok(()) => {}
                        Err(err) => {
                            if !matches!(err, tungstenite::Error::ConnectionClosed) {
                                log::error!("Websocket connection error: {}", err);
                            }
                        }
                    }
                }
            });
        }
    }

    pub async fn peer_discovery_client(
        state: ServiceState,
        service_sender: async_channel::Sender<ControlServerMessage>,
        socket_addr: SocketAddr,
    ) {
        async_std::task::spawn(async move {
            log::info!("Connecting to {}", socket_addr);
            let stream = TcpStream::connect(socket_addr).await.unwrap();
            let server_url = url::Url::parse(&format!("ws://{}/v1", socket_addr)).unwrap();
            let (mut ws, _response) = async_tungstenite::client_async(server_url, stream)
                .await
                .unwrap();
            let mut connection = ControlServerConnection::new(
                &mut ws,
                service_sender,
                true,
                state,
                socket_addr.ip(),
            );
            connection.client_discovery_connection().await.unwrap();
        });
    }

    async fn connect_any(
        socket_addrs: impl IntoIterator<Item = &SocketAddr>,
    ) -> Option<(TcpStream, SocketAddr)> {
        for addr in socket_addrs {
            log::trace!("Try connect {}", addr);
            let stream_res = TcpStream::connect(addr).await;
            match stream_res {
                Ok(stream) => {
                    return Some((stream, *addr));
                }
                Err(err) => {
                    log::warn!("Connection failed {}", err);
                    // Ignore error and try different address
                }
            }
        }

        None
    }

    pub fn initiate_transfer(
        state: ServiceState,
        peer_id: String,
        service_sender: async_channel::Sender<ControlServerMessage>,
    ) -> Result<(), ConnectionError> {
        log::info!("Connecting to {}", peer_id);
        let Some(peer_addrs) = state.read().peers.get(&peer_id).map(|peer| peer.socket_addrs.clone()) else {
            return Err(ConnectionError::InvalidState);
        };

        async_std::task::spawn(async move {
            if let Some((connection, socket_addr)) = Self::connect_any(&peer_addrs).await {
                log::debug!("Connected");
                let server_url = url::Url::parse(&format!("ws://{}/v1", socket_addr)).unwrap();
                let (mut ws, _response) = async_tungstenite::client_async(server_url, connection)
                    .await
                    .unwrap();
                let mut connection = ControlServerConnection::new(
                    &mut ws,
                    service_sender,
                    true,
                    state,
                    socket_addr.ip(),
                );
                connection.client_request_transfer().await.unwrap();
            }
        });

        Ok(())
    }

    async fn ping_peer(
        peer_id: &str,
        addrs: impl IntoIterator<Item = &SocketAddr>,
        state: ServiceState,
        service_sender: async_channel::Sender<ControlServerMessage>,
    ) -> bool {
        let Some((connection, socket_addr)) = Self::connect_any(addrs).await else {
            return false;
        };

        log::trace!("Ping {}", socket_addr);

        let server_url = url::Url::parse(&format!("ws://{}/v1", socket_addr)).unwrap();
        let res = async_tungstenite::client_async(server_url, connection).await;

        let Ok((mut ws, _response)) = res else {
            return false;
        };

        let mut client =
            ControlServerConnection::new(&mut ws, service_sender, true, state, socket_addr.ip());
        let pong = client.client_ping(peer_id).await;
        if pong {
            log::trace!("Pong");
        }

        pong
    }

    pub async fn peer_ping_service(
        state: ServiceState,
        service_sender: async_channel::Sender<ControlServerMessage>,
    ) {
        let mut ping_id: u32 = 0;

        loop {
            // This will wake every 30 seconds and ping all peers to see if they are still there
            async_io::Timer::after(Duration::from_secs(30)).await;
            let mut peer_addrs = HashMap::new();
            for (peer_id, peer) in &state.read().peers {
                log::debug!("Addrs: {:?}", peer.socket_addrs);
                peer_addrs.insert(peer_id.clone(), peer.socket_addrs.clone());
            }

            // Now we ping all the peers
            for (peer_id, addrs) in peer_addrs {
                log::debug!("Will try to ping {:?}", addrs);
                let keep_peer =
                    Self::ping_peer(&peer_id, &addrs, state.clone(), service_sender.clone()).await;

                if !keep_peer {
                    state.write().peers.remove(&peer_id);
                    let res = service_sender
                        .send(ControlServerMessage::PeerRemoved {
                            peer_id: peer_id.clone(),
                        })
                        .await;
                    if res.is_err() {
                        log::error!("Error sending control server message");
                    }
                }
            }

            ping_id = ping_id.wrapping_add(1);
        }
    }
}

// This Mutex ensures that handshakes don't occur at the same time
// If they did we could have more than one key per peer which is undesirable
pub static HANDSHAKE_LOCK: async_std::sync::Mutex<()> = async_std::sync::Mutex::new(());

// This Mutex ensures that authentications don't occur at the same time
pub static AUTHENTICATION_LOCK: async_std::sync::Mutex<()> = async_std::sync::Mutex::new(());

struct ControlServerConnection<'a, T> {
    websocket: &'a mut WebSocketStream<T>,
    peer_control_port: Option<u16>,
    service_sender: async_channel::Sender<ControlServerMessage>,
    is_client: bool,
    initiated_transfer: bool,
    state: ServiceState,
    peer_id: Option<String>,
    cipher: Option<MessageCipher>,
    challenge: Option<Vec<u8>>,
    peer_ip: IpAddr,
}

impl<'a, T> ControlServerConnection<'a, T>
where
    T: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    pub fn new(
        websocket: &'a mut WebSocketStream<T>,
        service_sender: async_channel::Sender<ControlServerMessage>,
        is_client: bool,
        state: ServiceState,
        peer_addr: IpAddr,
    ) -> Self {
        Self {
            websocket,
            peer_control_port: None,
            service_sender,
            is_client,
            initiated_transfer: false,
            state,
            peer_id: None,
            cipher: None,
            challenge: None,
            peer_ip: peer_addr,
        }
    }

    fn peer_control_socket_addr(&self) -> Option<SocketAddr> {
        if let Some(port) = self.peer_control_port {
            Some(SocketAddr::new(self.peer_ip, port))
        } else {
            None
        }
    }

    pub async fn send_msg(&mut self, msg: &ControlMessage) -> Result<(), tungstenite::Error> {
        let json = serde_json::to_string(msg).unwrap();
        if !matches!(msg, ControlMessage::EncryptedMessage { .. }) {
            log::trace!("Send: {}", json);
        }
        self.websocket.send(json.into()).await
    }

    pub async fn send_encrypted_msg(
        &mut self,
        msg: DecryptedMessage,
    ) -> Result<(), ConnectionError> {
        let Some(cipher) = &mut self.cipher else {
            return Err(ConnectionError::CryptoError);
        };

        log::trace!("Send: {:?}", msg);

        let enc_msg = cipher.encrypt_message(&msg)?;
        Ok(self
            .send_msg(&ControlMessage::EncryptedMessage { data: enc_msg })
            .await?)
    }

    async fn receive_msg(&mut self) -> Result<ControlMessage, ConnectionError> {
        while let Some(Ok(msg)) = self.websocket.next().await {
            return match msg {
                tungstenite::Message::Text(msg_txt) => {
                    let client_msg = serde_json::from_str(&msg_txt);
                    if !matches!(client_msg, Ok(ControlMessage::EncryptedMessage { .. })) {
                        log::trace!("Receive: {}", msg_txt);
                    }

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

        let msg = cipher.decrypt_message(&encrypted)?;
        log::trace!("Receive: {:?}", msg);

        if let Some(peer_id) = &self.peer_id {
            // We received an encrypted message from a known peer, we can add the address
            // to the list of valid (verified) socket addrs
            if let Some(peer) = self.state.write().peers.get_mut(peer_id) {
                if let Some(socket_addr) = self.peer_control_socket_addr() {
                    peer.socket_addrs.insert(socket_addr);
                }
            }
        }

        Ok(msg)
    }

    async fn alloc_wormhole(&mut self) -> String {
        let mut rng = rand::rngs::OsRng::default();
        let nameplate: u32 = rng.gen_range(10_000..1_000_000);

        let mut random_bytes = [0u8; 32];
        rng.fill_bytes(&mut random_bytes);
        let hk = hkdf::Hkdf::<Sha256>::new(None, &random_bytes);
        let mut code_bytes = [0u8; 64];
        hk.expand(b"code", &mut code_bytes)
            .expect("64 is a valid length for Sha256 to output");
        let password = hex::encode(code_bytes);
        format!("{nameplate}-{password}")
    }

    /// Returns Ok(false) if the connection was terminated
    async fn handle_decrypted_message(
        &mut self,
        msg: &DecryptedMessage,
    ) -> Result<(), ConnectionError> {
        let Some(authenticated_peer) = self.peer_id.as_ref().and_then(|id| self.state.read().peers.get(id).map(|peer| peer.authenticated)) else {
            return Err(ConnectionError::InvalidState);
        };

        match msg {
            DecryptedMessage::RequestInfo => {
                let my_info = self.state.read().my_info.clone();
                self.send_encrypted_msg(DecryptedMessage::Info(my_info))
                    .await?;
            }
            DecryptedMessage::Info(peer_info) => {
                log::info!("Received peer info: {:?}", peer_info);
                let peer_id = peer_info.service_uuid.clone();
                self.peer_id = Some(peer_id.clone());

                let peer_info = {
                    // This block is needed to scope the lock for the await below
                    let mut lock = self.state.write();
                    if !lock.peers.contains_key(&peer_info.service_uuid) {
                        if peer_info.service_uuid == lock.my_info.service_uuid {
                            log::debug!("Accidentally connected to myself");
                            return Err(ConnectionError::PeerExists);
                        }

                        // We should have had this peer registered in the handshake
                        return Err(ConnectionError::InvalidState);
                    } else {
                        log::debug!("Peer already exists, checking key validity");
                        let Some(peer) = lock.peers
                            .get_mut(&peer_info.service_uuid) else {
                            return Err(ConnectionError::InvalidState);
                        };

                        // Update the info and ip addresses
                        peer.update_message(peer_info.clone());
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
                if !authenticated_peer {
                    self.send_encrypted_msg(DecryptedMessage::AuthenticationResult(false))
                        .await?;
                } else if !self.initiated_transfer {
                    self.send_encrypted_msg(DecryptedMessage::InitiateTransferResult(false))
                        .await?;
                } else {
                    let Some(peer_id) = self.peer_id.clone() else {
                        return Err(ConnectionError::InvalidState);
                    };

                    let port = self.state.read().rendezvous_port;
                    let code = self.alloc_wormhole().await;

                    self.send_encrypted_msg(DecryptedMessage::Wormhole {
                        port,
                        code: code.clone(),
                    })
                    .await?;

                    // We are the server, therefore the server address is localhost
                    let mailbox_addr =
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
                    log::info!(
                        "Allocated wormhole: {}, mailbox server port: {}",
                        code,
                        port
                    );

                    self.service_sender
                        .send(ControlServerMessage::AllocatedWormhole {
                            send: false,
                            peer_id,
                            mailbox_addr,
                            code,
                        })
                        .await
                        .map_err(|_| ConnectionError::InvalidState)?;
                }
            }
            DecryptedMessage::Wormhole { port, code } => {
                if !authenticated_peer {
                    self.send_encrypted_msg(DecryptedMessage::AuthenticationResult(true))
                        .await?;
                } else {
                    let Some(peer_id) = self.peer_id.clone() else {
                        return Err(ConnectionError::InvalidState);
                    };

                    // We are the client, so we connect to the server mailbox
                    let mailbox_addr = SocketAddr::new(self.peer_ip, *port);

                    self.service_sender
                        .send(ControlServerMessage::AllocatedWormhole {
                            send: true,
                            peer_id,
                            mailbox_addr,
                            code: code.clone(),
                        })
                        .await
                        .map_err(|_| ConnectionError::InvalidState)?;
                }
            }
            DecryptedMessage::InitiateTransfer => {
                let Some(peer_id) = self.peer_id.clone() else {
                    return Err(ConnectionError::InvalidState);
                };

                // Ask the client if we should initiate a transfer
                let (result_sender, result_receiver) = async_channel::unbounded();
                let result_fn = move |result| {
                    result_sender.send_blocking(result).unwrap();
                };

                self.service_sender
                    .send(ControlServerMessage::RequestInitiateTransfer {
                        peer_id,
                        result_fn: Box::new(result_fn),
                    })
                    .await
                    .map_err(|_| ConnectionError::InvalidState)?;

                let should_initiate = result_receiver
                    .recv()
                    .await
                    .map_err(|_| ConnectionError::InvalidState)?;
                self.send_encrypted_msg(DecryptedMessage::InitiateTransferResult(should_initiate))
                    .await?;

                if should_initiate {
                    self.initiated_transfer = true;
                    self.authenticate_peer(false).await?;
                }
            }
            DecryptedMessage::InitiateTransferResult(result) => {
                if !result {
                    let Some(peer_id) = self.peer_id.clone() else {
                        return Err(ConnectionError::InvalidState);
                    };

                    log::error!("The peer {} has denied the transfer request", peer_id);
                } else {
                    log::error!(
                        "Unexpected successful transfer initiation result in main msg handler"
                    );
                }
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
                log::error!("unexpected message received {:?}", msg);
                return Err(ConnectionError::CryptoError);
            }
        }

        Ok(())
    }

    pub async fn handle_connection(&mut self) -> Result<(), ConnectionError> {
        self.handshake().await?;

        while !self.websocket.is_terminated() {
            let msg = self.receive_encrypted_msg().await?;
            self.handle_decrypted_message(&msg).await?;
        }

        log::debug!("Closing server connection");

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
        let authentication_lock = AUTHENTICATION_LOCK.lock().await;
        log::info!("authenticate_peer");
        let my_pubkey = self.state.read().device_key.public_key().to_vec();
        let Some(peer_id) = self.peer_id.clone() else {
            log::error!("Peer doesn't exist in list of known peers");
            return Err(ConnectionError::InvalidState);
        };

        let Some(their_pubkey) = &self.state.read().peers.get(&peer_id).map(|peer| peer.public_key.clone()) else {
            log::error!("No public key found");
            return Err(ConnectionError::CryptoError);
        };

        let mut do_user_auth = true;

        if self.state.read().authorized_keys.contains(their_pubkey)
            || self
                .state
                .read()
                .peers
                .get(&peer_id)
                .map_or(false, |peer| peer.authenticated)
        {
            // We already authenticated the user. Now let's see if our peer agrees
            self.send_encrypted_msg(DecryptedMessage::AuthenticationResult(true))
                .await?;
            let msg = self.receive_encrypted_msg().await?;
            match msg {
                DecryptedMessage::UserAuthenticate => {
                    // Fall through and go through user authentication flow
                }
                DecryptedMessage::AuthenticationResult(success) => {
                    if success {
                        // We agree that we don't need verification
                        if let Some(peer) = self.state.write().peers.get_mut(&peer_id) {
                            peer.authenticated = true
                        }
                        do_user_auth = false;
                    } else {
                        log::info!("Authentication failed");
                        return Err(ConnectionError::CryptoError);
                    }
                }
                _ => {
                    log::error!("Expected authentication message");
                    return Err(ConnectionError::CryptoError);
                }
            }
        }

        if do_user_auth {
            // We need to use user authentication
            log::info!("User authentication");
            self.send_encrypted_msg(DecryptedMessage::UserAuthenticate)
                .await?;

            let Some(sas_secret) = self.state.read().peers.get(&peer_id).map(|peer| peer.sas_secret) else {
                return Err(ConnectionError::InvalidState);
            };

            // Calculate SAS
            let sas = Sas::new_hkdf_sha265(&sas_secret, &my_pubkey, their_pubkey, is_client);
            let (emoji, verbose_emoji) = sas.get_emoji_string(6);
            log::debug!("Authentication SAS emoji: {}", verbose_emoji);

            let (result_sender, result_receiver) = async_channel::unbounded();
            let result_fn = move |result| {
                result_sender.send_blocking(result).unwrap();
            };

            self.service_sender
                .send(ControlServerMessage::CompareEmoji {
                    peer_id: peer_id.clone(),
                    emoji,
                    verbose_emoji,
                    result_fn: Box::new(result_fn),
                })
                .await
                .map_err(|_| ConnectionError::InvalidState)?;

            let result = result_receiver
                .recv()
                .await
                .map_err(|_| ConnectionError::InvalidState)?;
            self.send_encrypted_msg(DecryptedMessage::AuthenticationResult(result))
                .await?;

            loop {
                let msg = self.receive_encrypted_msg().await?;
                match msg {
                    DecryptedMessage::UserAuthenticate => {
                        // They want to authenticate as well
                    }
                    DecryptedMessage::AuthenticationResult(success) => {
                        if let Some(peer) = self.state.write().peers.get_mut(&peer_id) {
                            peer.authenticated = success;
                        }
                        self.service_sender
                            .send(ControlServerMessage::CompareEmojiPeerResult {
                                peer_id: peer_id.clone(),
                                result: success,
                            })
                            .await
                            .map_err(|_| ConnectionError::InvalidState)?;

                        if success {
                            log::info!("Authentication success!");
                            break;
                        } else {
                            log::info!("Authentication failed");
                            return Err(ConnectionError::CryptoError);
                        }
                    }
                    _ => {
                        log::error!("Expected authentication message");
                        return Err(ConnectionError::CryptoError);
                    }
                }
            }
        }

        drop(authentication_lock);

        Ok(())
    }

    pub async fn handshake(&mut self) -> Result<(), ConnectionError> {
        log::info!("Handshake");
        // Keep this locked for the whole function
        let handshake_lock = HANDSHAKE_LOCK.lock().await;

        // Now that we have the lock we can make some assumptions:
        // 1. No handshake will occur at the same time
        // 2. As only the handshake sets the shared secret, this will be in a stable state:
        //    We either have one, or we don't and need to do a key exchange

        // Find out the peer id key. Anyone could claim they are a specific peer, but we will verify
        // this later after key exchange with the ed25519 certificate
        let my_id = self.state.read().my_info.service_uuid.clone();
        let control_port = self.state.read().control_port;
        self.send_msg(&ControlMessage::Welcome {
            id: my_id.clone(),
            control_port,
        })
        .await?;
        let msg = self.receive_msg().await?;
        let (peer_id, peer_control_port) = match msg {
            ControlMessage::Welcome {
                id,
                control_port: peer_control_port,
            } => (id, peer_control_port),
            _ => {
                return Err(ConnectionError::InvalidState);
            }
        };
        self.peer_id = Some(peer_id.clone());
        self.peer_control_port = Some(peer_control_port);

        // Now that we have the peer id we can check if we already made a handshake with this peer
        // or someone claiming to be this peer.
        // If the latter, they won't be able to do anything with our encrypted messages
        let maybe_cipher = {
            self.state
                .read()
                .peers
                .get(&peer_id)
                .map(|peer| peer.cipher.clone())
        };

        if let Some(cipher) = maybe_cipher {
            self.cipher = Some(cipher);

            // Now we just continue sending encrypted messages. The peer is supposed to save the
            // cipher and know how to read them. If they don't something strange might be going
            // on. If they don't agree with this we will be receiving a
            // `ControlMessage::KeyExchangeX25519` from them which will abort the conversation.
            // We are perfectly happy with this. As peers will generate a new ID when they restart
            // there won't be any collisions here.
        } else {
            // Peer is unknown to us, we do a proper key exchange
            log::debug!("Key exchange");

            // Key exchange. We generate ephemeral secrets on both sides and use ECDH with x25519
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

            // Now we derive two keys: First one is the cipher key we use for encryption
            let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());

            // The cipher key needs to be 64 bytes long
            let mut cipher_key = [0u8; 32];
            hk.expand(b"cipher", &mut cipher_key)
                .expect("64 is a valid length for Sha256 to output");
            let cipher = MessageCipher::from_secret(&cipher_key);
            self.cipher = Some(cipher);

            // The second key to be derived is the SAS secret we use for peer authentication later
            let mut sas_secret = [0u8; 32];
            hk.expand(b"sas", &mut sas_secret)
                .expect("32 is a valid length for Sha256 to output");

            // Now we have a cipher, let's continue encrypted
            let mut challenge = vec![64u8; 64];
            rand::rngs::OsRng::default().fill_bytes(&mut challenge);
            self.challenge = Some(challenge.clone());

            self.send_encrypted_msg(DecryptedMessage::KeyVerificationEd25519 { challenge })
                .await?;

            let mut other_verified_key = false;
            let mut verified_key = false;
            let mut peer_key = None;
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

                            // Concatenate our public key, our peer id and challenge
                            // This proves that id and public key match, and that we own the private key
                            let mut data = challenge.clone();
                            data.extend_from_slice(&public_key);
                            data.extend_from_slice(my_id.as_bytes());
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

                        log::trace!("Challenge: {:?}", challenge);

                        // Check if the signature matches the challenge + key
                        let mut data = challenge.clone();
                        data.extend_from_slice(&public_key);
                        data.extend_from_slice(peer_id.as_bytes());
                        let key = DevicePublicKey::from_data(&public_key)
                            .ok_or(ConnectionError::CryptoError)?;
                        if !key.verify(&data, &signature) {
                            return Err(ConnectionError::CryptoError);
                        } else {
                            verified_key = true;
                            peer_key = Some(public_key);
                        }

                        self.challenge = None;
                    }
                    _ => {
                        log::error!("Unexpected message, expected key verification");
                        return Err(ConnectionError::CryptoError);
                    }
                }
            }

            log::info!("Verified the public key of peer");

            // Insert the peer into peer list
            let (Some(peer_key), Some(cipher)) = (&peer_key, &self.cipher) else {
                return Err(ConnectionError::InvalidState);
            };

            let mut peer = Peer::with_key(peer_key.clone(), sas_secret, cipher.clone());
            if let Some(socket_addr) = self.peer_control_socket_addr() {
                peer.socket_addrs.insert(socket_addr);
            }
            self.state.write().peers.insert(peer_id, peer);
        };

        // Make sure the handshake lock exists until the end of this function.
        // drop consumes the lock, therefore it must exist up until this point.
        drop(handshake_lock);
        Ok(())
    }

    pub async fn client_discovery_connection(&mut self) -> Result<(), ConnectionError> {
        log::info!("Client connection");
        self.handshake().await?;

        self.send_encrypted_msg(DecryptedMessage::RequestInfo)
            .await?;
        // This will err if peer already exists
        let msg = self.receive_encrypted_msg().await?;
        self.handle_decrypted_message(&msg).await?;

        Ok(())
    }

    pub async fn client_request_transfer(&mut self) -> Result<(), ConnectionError> {
        self.handshake().await?;

        let Some(peer_id) = self.peer_id.clone() else {
            return Err(ConnectionError::InvalidState);
        };
        log::debug!("Authenticating peer connection");
        self.send_encrypted_msg(DecryptedMessage::InitiateTransfer)
            .await?;
        let msg = self.receive_encrypted_msg().await?;
        match msg {
            DecryptedMessage::InitiateTransferResult(result) => {
                self.initiated_transfer = result;

                if !result {
                    log::error!("The peer didn't allow the transfer");
                    self.service_sender
                        .send(ControlServerMessage::InitiateTransferPeerResult {
                            peer_id,
                            result: false,
                        })
                        .await
                        .map_err(|_| ConnectionError::InvalidState)?;
                    return Ok(());
                } else {
                    log::info!("The peer accepted our transfer request");
                }
            }
            _ => {
                log::error!("Unexpected message, expected InitiateTransferResult");
                return Err(ConnectionError::InvalidState);
            }
        }
        self.authenticate_peer(true).await?;

        log::info!("Allocating wormhole");
        self.send_encrypted_msg(DecryptedMessage::AllocWormhole)
            .await?;
        let msg = self.receive_encrypted_msg().await?;
        self.handle_decrypted_message(&msg).await?;
        self.websocket.close(None).await?;

        Ok(())
    }

    pub async fn client_ping(&mut self, peer_id: &str) -> bool {
        if let Ok(msg) = self.receive_msg().await {
            match msg {
                ControlMessage::Welcome {
                    id,
                    control_port: _,
                } => {
                    if peer_id == id {
                        return true;
                    }
                }
                _ => {
                    return false;
                }
            }
        }

        false
    }
}
