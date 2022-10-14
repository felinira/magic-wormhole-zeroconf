use crate::control::message::PeerInfoMessage;
use crate::control::server::{ConnectionError, ControlServer, ControlServerMessage, Peer};
use crate::key;
use crate::key::device::DeviceKeyPair;
use crate::state::ServiceState;
use crate::zeroconf::{ZeroconfBrowser, ZeroconfEvent, ZeroconfService, ZeroconfServiceDiscovery};
use async_tungstenite::tungstenite::protocol::frame::coding::OpCode::Control;
use futures::{select, FutureExt};
use magic_wormhole_mailbox::{rendezvous_server, RendezvousServer};
use std::collections::HashSet;
use std::net::AddrParseError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use sysinfo::SystemExt;
use zeroconf::prelude::*;
use zeroconf::ServiceDiscovery;

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("Internal error: {}", _0)]
    InternalError(String),
    #[error("Connection error")]
    ConnectionError {
        #[from]
        source: ConnectionError,
    },
}

/// These messages are sent from the service to the application
pub enum ServiceMessage {
    ServiceStarted,
    ServiceStopped,
    ServiceError(ServiceError),
    PeerAddedUpdated {
        peer_id: String,
        peer_info: PeerInfoMessage,
    },
    PeerRemoved {
        peer_id: String,
    },
    RequestInitiateTransfer {
        peer_id: String,
    },
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
}

/// These messages are sent from the application to the service
#[derive(Clone, Debug)]
pub enum ServiceRequest {
    InitiateTransfer { peer_id: String },
    SetAuthorizedKeys(HashSet<Vec<u8>>),
    StopService,
}

pub struct Service {
    state: ServiceState,

    service_sender: async_channel::Sender<ServiceMessage>,
    request_receiver: Option<async_channel::Receiver<ServiceRequest>>,

    control_server_receiver: async_channel::Receiver<ControlServerMessage>,
    control_server_sender: async_channel::Sender<ControlServerMessage>,

    stop_handle: Arc<AtomicBool>,
}

impl Service {
    pub fn new(
        device_key: DeviceKeyPair,
    ) -> (
        async_channel::Sender<ServiceRequest>,
        async_channel::Receiver<ServiceMessage>,
        Self,
    ) {
        let my_id = uuid::Uuid::new_v4();
        let my_info = Self::system_peer_info(my_id.to_string());

        let (service_sender, service_receiver) = async_channel::unbounded();
        let (request_sender, request_receiver) = async_channel::unbounded();
        let (control_server_sender, control_server_receiver) = async_channel::unbounded();
        let state = ServiceState::new(my_info, device_key, service_sender.clone());

        (
            request_sender,
            service_receiver,
            Self {
                state,

                service_sender,
                request_receiver: Some(request_receiver),
                control_server_receiver,
                control_server_sender,

                stop_handle: Arc::default(),
            },
        )
    }

    fn system_peer_info(my_id: String) -> PeerInfoMessage {
        let system_info = sysinfo::System::new();

        PeerInfoMessage::new(
            system_info.host_name().unwrap_or("?".to_string()),
            my_id,
            None,
            None,
        )
    }

    async fn handle_service_discovered(
        &self,
        discovery: &ZeroconfServiceDiscovery,
    ) -> Result<(), ServiceError> {
        let my_id = &self.state.read().my_info.service_uuid.clone();
        let txt = match &discovery.txt {
            None => return Ok(()),
            Some(txt) => txt,
        };

        let Some(peer_id) = txt.get("uuid") else {
            println!("No uuid specified in mDNS txt record");
            return Ok(());
        };

        if peer_id == my_id {
            println!("Discovered myself");
            return Ok(());
        }

        let control_port = discovery.port;

        // Connect to the control port
        let socket_addr = if discovery.address.contains(":") {
            // This is an IPv6 address
            // TODO: Is there a better way?
            format!("[{}]:{}", discovery.address, control_port)
                .parse()
                .map_err(|err: AddrParseError| ServiceError::InternalError(err.to_string()))?
        } else {
            format!("{}:{}", discovery.address, control_port)
                .parse()
                .map_err(|err: AddrParseError| ServiceError::InternalError(err.to_string()))?
        };

        // Run connection in the background
        ControlServer::peer_discovery_client(
            self.state.clone(),
            self.control_server_sender.clone(),
            socket_addr,
        )
        .await;

        Ok(())
    }

    async fn handle_service_registered(&self) -> Result<(), ServiceError> {
        self.service_sender
            .send(ServiceMessage::ServiceStarted)
            .await
            .map_err(|_| ServiceError::InternalError("async channel closed".to_string()))?;

        Ok(())
    }

    async fn initiate_transfer(&self, peer_id: &str) -> Result<(), ServiceError> {
        ControlServer::initiate_transfer(
            self.state.clone(),
            peer_id.to_string(),
            self.control_server_sender.clone(),
        )?;
        Ok(())
    }

    async fn handle_request(&mut self, request: &ServiceRequest) -> Result<(), ServiceError> {
        match request {
            ServiceRequest::InitiateTransfer { peer_id } => {
                self.initiate_transfer(peer_id).await?;
            }
            ServiceRequest::SetAuthorizedKeys(keys) => {
                // We need all locks
                let handshake_lock = crate::control::server::HANDSHAKE_LOCK.lock().await;
                let mut state_lock = self.state.write();

                state_lock.authorized_keys = keys.clone();
                for peer in state_lock.peers.values_mut() {
                    // Unauthenticate peer if not in the list anymore
                    let pubkey = &peer.public_key;
                    if !keys.contains(pubkey) {
                        peer.authenticated = false;
                    }
                }

                drop(handshake_lock);
                drop(state_lock);
            }
            ServiceRequest::StopService => {
                self.stop_handle.store(true, Ordering::Relaxed)
                // This will return and the run loop will exit
            }
        }

        Ok(())
    }

    async fn handle_control_server_msg(
        &mut self,
        msg: ControlServerMessage,
    ) -> Result<(), ServiceError> {
        match msg {
            ControlServerMessage::CompareEmoji {
                peer_id,
                emoji,
                verbose_emoji,
                result_fn,
            } => {
                self.service_sender
                    .send(ServiceMessage::CompareEmoji {
                        peer_id,
                        emoji,
                        verbose_emoji,
                        result_fn,
                    })
                    .await
                    .map_err(|_| ServiceError::InternalError("Channel closed".to_string()))?;
            }
            ControlServerMessage::CompareEmojiPeerResult { peer_id, result } => {
                self.service_sender
                    .send(ServiceMessage::CompareEmojiPeerResult { peer_id, result })
                    .await
                    .map_err(|_| ServiceError::InternalError("Channel closed".to_string()))?;
            }
        }

        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), ServiceError> {
        let mut rendezvous_server = RendezvousServer::run(0).await.unwrap();
        println!(
            "Rendezvous: Listening on port: {}",
            rendezvous_server.port()
        );
        self.state.write().rendezvous_port = rendezvous_server.port();
        let my_id = self.state.read().my_info.service_uuid.clone();

        let mut control_server = ControlServer::run(self.state.clone(), 0)
            .await
            .map_err(|err| ServiceError::InternalError(err.to_string()))?;
        println!("Control: Listening on port: {}", control_server.port());

        let (zeroconf_sender, zeroconf_receiver) = async_channel::unbounded();
        let mut zeroconf_service =
            ZeroconfService::spawn(control_server.port(), my_id, zeroconf_sender.clone());
        let mut zeroconf_browser = ZeroconfBrowser::spawn(zeroconf_sender);
        let request_receiver = self.request_receiver.take().unwrap();

        while !self.stop_handle.load(Ordering::Relaxed) {
            println!("Listening for events");
            select! {
                msg_res = zeroconf_receiver.recv().fuse() => if let Ok(msg) = &msg_res {
                    match msg {
                        ZeroconfEvent::ServiceDiscovered(discovery) => {
                            println!("Service discovered event");
                            self.handle_service_discovered(discovery).await?;
                        },
                        ZeroconfEvent::ServiceRegistered => {
                            self.handle_service_registered().await?;
                        },
                        ZeroconfEvent::Error(err) => {
                            println!("Zeroconf error: {:?}", err);
                        }
                    }
                },
                msg_res = Box::pin(request_receiver.recv()).fuse() => if let Ok(msg) = &msg_res {
                    self.handle_request(msg).await?;
                },
                () = Box::pin(rendezvous_server.wait_for_connection()).fuse() =>
                    println!("Rendezvous server stopped"),
                () = Box::pin(control_server.wait_for_connection(self.control_server_sender.clone())).fuse() =>
                    println!("Control server stopped"),
                msg_res = self.control_server_receiver.recv().fuse() => if let Ok(msg) = msg_res {
                    self.handle_control_server_msg(msg).await?;
                }
            }
        }

        // Stop everything
        zeroconf_service.runner.stop();
        zeroconf_browser.runner.stop();
        control_server.stop().await;
        rendezvous_server.stop().await;

        Ok(())
    }
}
