//! Control socket used for initial connection and wormhole establishment

use async_std::net::TcpStream;
use async_tungstenite::{tungstenite, WebSocketStream};
use futures::stream::FusedStream;
use futures::{SinkExt, StreamExt};
use parking_lot::RwLock;
use serde_derive::{Deserialize, Serialize};
use serde_json;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::hash::Hash;
use std::net::SocketAddr;
use std::sync::Arc;

const APP_ID: &'static str = "app.drey.Warp.zeroconf0";

#[derive(Debug, thiserror::Error)]
#[must_use]
pub enum ConnectionError {
    #[error("I/O error")]
    IO {
        #[from]
        #[source]
        source: std::io::Error,
    },
    #[error("Error parsing JSON message: {:?}", _0)]
    JsonParse(String),
    #[error("Received unexpected message type: {:?}", _0)]
    UnexpectedType(tungstenite::Message),
    #[error("WebSocket error: {}", source)]
    WebSocket {
        #[from]
        #[source]
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
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    #[serde(skip)]
    pub socket_addrs: HashSet<SocketAddr>,
    pub machine_name: String,
    pub session_id: String,
    pub user_name: Option<String>,
    pub user_picture: Option<Vec<u8>>,
}

impl PeerInfo {
    pub fn new(
        machine_name: String,
        session_id: String,
        user_name: Option<String>,
        user_picture: Option<Vec<u8>>,
    ) -> Self {
        Self {
            socket_addrs: HashSet::new(),
            machine_name,
            session_id,
            user_name,
            user_picture,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "type")]
enum ControlMessage {
    RequestInfo,
    Info(PeerInfo),
    AllocWormhole,
    Verify,
    Verified,
    NotVerified,
    Wormhole { code: String },
    Remove,
}

/// These messages are sent from the client to the connected peers.
enum PeerControl {
    ConnectWormholeURL(String),
    Close,
}

#[derive(Default)]
pub struct ControlServerStateInner {
    pub my_info: PeerInfo,
    pub peers: HashMap<String, PeerInfo>,
}

pub type ControlServerState = Arc<RwLock<ControlServerStateInner>>;

pub struct ControlServer {
    listener: async_std::net::TcpListener,
    state: ControlServerState,
}

impl ControlServer {
    pub async fn run(port: u16, my_info: PeerInfo) -> Result<Self, std::io::Error> {
        let addrs: [async_std::net::SocketAddr; 2] = [
            format!("[::]:{}", port).parse().unwrap(),
            format!("0.0.0.0:{}", port).parse().unwrap(),
        ];

        let listener = async_std::net::TcpListener::bind(&addrs[..]).await?;
        let state = Arc::new(RwLock::new(ControlServerStateInner {
            my_info,
            peers: Default::default(),
        }));

        Ok(Self { listener, state })
    }

    pub fn port(&self) -> u16 {
        self.listener.local_addr().unwrap().port()
    }

    pub fn state(&self) -> ControlServerState {
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

    pub async fn connect_to_peer(state: ControlServerState, socket_addr: SocketAddr) {
        async_std::task::spawn(async move {
            println!("Connecting to {}", socket_addr);
            let stream = TcpStream::connect(socket_addr).await.unwrap();
            println!("Connected");
            let server_url =
                url::Url::parse(&format!("ws://{}/v1", socket_addr.to_string())).unwrap();
            let (mut ws, response) = async_tungstenite::client_async(server_url, stream)
                .await
                .unwrap();
            let mut connection = ControlServerConnection::new(&mut ws, state, socket_addr);
            connection.client_connection().await.unwrap();
        });
    }
}

struct ControlServerConnection<'a, T> {
    websocket: &'a mut WebSocketStream<T>,
    state: ControlServerState,
    peer_id: Option<String>,
    verified: bool,
    peer_addr: SocketAddr,
}

impl<'a, T> ControlServerConnection<'a, T>
where
    T: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    pub fn new(
        websocket: &'a mut WebSocketStream<T>,
        state: ControlServerState,
        peer_addr: SocketAddr,
    ) -> Self {
        Self {
            websocket,
            state,
            peer_id: None,
            verified: false,
            peer_addr,
        }
    }

    pub async fn send_msg(&mut self, msg: &ControlMessage) -> Result<(), tungstenite::Error> {
        let json = serde_json::to_string(msg).unwrap();
        println!("Send: {}", json);
        self.websocket.send(json.into()).await
    }

    async fn receive_msg(&mut self) -> Result<ControlMessage, ConnectionError> {
        while let Some(Ok(msg)) = self.websocket.next().await {
            return match msg {
                tungstenite::Message::Text(msg_txt) => {
                    println!("Receive: {}", msg_txt);
                    let client_msg = serde_json::from_str(&msg_txt);
                    client_msg.map_err(|err| ConnectionError::JsonParse(msg_txt))
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

    async fn alloc_code(&mut self) -> String {
        "23-abc-def".to_string()
    }

    /// Returns Ok(false) if the connection was terminated
    async fn handle_message(&mut self, msg: &ControlMessage) -> Result<(), ConnectionError> {
        match msg {
            ControlMessage::RequestInfo => {
                let my_info = self.state.read().my_info.clone();
                self.send_msg(&ControlMessage::Info(my_info)).await?;
            }
            ControlMessage::Info(peer_info) => {
                println!("Received peer info: {:?}", peer_info);
                let peer_addr = self.peer_addr.clone();
                let peer_id = peer_info.session_id.clone();
                self.peer_id = Some(peer_id.clone());
                let mut lock = self.state.write();

                if !lock.peers.contains_key(&peer_info.session_id) {
                    if peer_info.session_id == lock.my_info.session_id {
                        println!("Accidentally connected to myself");
                        return Err(ConnectionError::PeerExists);
                    }

                    let mut peer_info = peer_info.clone();
                    peer_info.socket_addrs.insert(peer_addr);

                    lock.peers.insert(peer_id, peer_info);
                } else {
                    println!("Peer already exists");
                    lock.peers
                        .get_mut(&peer_info.session_id)
                        .map(|peer| peer.socket_addrs.insert(peer_addr));

                    return Err(ConnectionError::PeerExists);
                }
            }
            ControlMessage::AllocWormhole => {
                if !self.verified {
                    self.send_msg(&ControlMessage::NotVerified).await?;
                } else {
                    let code = self.alloc_code().await;
                    self.send_msg(&ControlMessage::Wormhole { code }).await?;
                }
            }
            ControlMessage::Wormhole { code } => {
                if !self.verified {
                    self.send_msg(&ControlMessage::NotVerified).await?;
                } else {
                    println!("Allocated wormhole: {}", code);
                }
            }
            ControlMessage::Verify => {
                // TODO: Crypto magic
                self.verified = true;
                self.send_msg(&ControlMessage::Verified).await?;
            }
            ControlMessage::Verified => {
                self.verified = true;
                // We can be happy but nothing really to do here
            }
            ControlMessage::NotVerified => {
                println!("Invalid verification message received from peer.");
                return Err(ConnectionError::VerificationFailed);
            }
            ControlMessage::Remove => {
                // Remove the peer from all discovery lists
                if let Some(peer_id) = &self.peer_id {
                    self.peer_id = None;
                    return Err(ConnectionError::Closed(None));
                }
            }
        }

        Ok(())
    }

    pub async fn handle_connection(&mut self) -> Result<(), ConnectionError> {
        while !self.websocket.is_terminated() {
            let msg = self.receive_msg().await?;
            self.handle_message(&msg).await?;
        }

        // TODO how to clean up client data?
        /*if let Some(peer_id) = &self.peer_id {
            // Remove the peer data because the connection got lost
            // This way the peers list semi-reliably only contains a list of online peers
            self.state.write().peers.remove(peer_id);
        }*/

        Ok(())
    }

    pub async fn client_connection(mut self) -> Result<(), ConnectionError> {
        println!("Client connection");
        self.send_msg(&ControlMessage::RequestInfo).await?;
        // This will err if peer already exists
        let msg = self.receive_msg().await?;
        self.handle_message(&msg).await?;

        println!("Verifying peer connection");
        self.send_msg(&ControlMessage::Verify).await?;
        // This will err if not verified
        let msg = self.receive_msg().await?;
        self.handle_message(&msg).await?;

        println!("Allocating wormhole");
        self.send_msg(&ControlMessage::AllocWormhole).await?;
        let msg = self.receive_msg().await?;
        self.handle_message(&msg).await?;
        self.websocket.close(None).await?;

        Ok(())
    }
}
