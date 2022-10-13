use crate::control::message::PeerInfoMessage;
use crate::control::server::{ControlServer, Peer};
use crate::key;
use crate::key::device::DeviceKeyPair;
use crate::state::ServiceState;
use crate::zeroconf::{ZeroconfBrowser, ZeroconfEvent, ZeroconfService};
use futures::{select, FutureExt};
use magic_wormhole_mailbox::rendezvous_server;
use std::collections::HashSet;
use std::net::AddrParseError;
use sysinfo::SystemExt;
use zeroconf::prelude::*;
use zeroconf::ServiceDiscovery;

#[derive(Clone, Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("Internal error: {}", _0)]
    InternalError(String),
}

/// These messages are sent from the service to the application
#[derive(Clone, Debug)]
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

    service_callback: Box<&'static dyn Fn(ServiceMessage)>,

    service_receiver: Option<async_channel::Receiver<ServiceMessage>>,
    service_sender: async_channel::Sender<ServiceMessage>,

    request_receiver: Option<async_channel::Receiver<ServiceRequest>>,
    request_sender: async_channel::Sender<ServiceRequest>,
}

impl Service {
    pub fn new(device_key: DeviceKeyPair, callback: &'static dyn Fn(ServiceMessage) -> ()) -> Self {
        let my_id = uuid::Uuid::new_v4();
        let my_info = Self::system_peer_info(my_id.to_string());

        let (service_sender, service_receiver) = async_channel::unbounded();
        let (request_sender, request_receiver) = async_channel::unbounded();
        let state = ServiceState::new(my_info, device_key, service_sender.clone());

        Self {
            state,

            service_callback: Box::new(callback),

            service_receiver: Some(service_receiver),
            service_sender,
            request_receiver: Some(request_receiver),
            request_sender,
        }
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
        discovery: &ServiceDiscovery,
    ) -> Result<(), ServiceError> {
        let my_id = &self.state.read().my_info.service_uuid.clone();
        let txt = match &discovery.txt() {
            None => return Ok(()),
            Some(txt) => txt,
        };

        let Some(peer_id) = txt.get("uuid") else {
            println!("No uuid specified in mDNS txt record");
            return Ok(());
        };

        if &peer_id == my_id {
            println!("Discovered myself");
            return Ok(());
        }

        let control_port = discovery.port();

        // Connect to the control port
        let socket_addr = if discovery.address().contains(":") {
            // This is an IPv6 address
            // TODO: Is there a better way?
            format!("[{}]:{}", discovery.address(), control_port)
                .parse()
                .map_err(|err: AddrParseError| ServiceError::InternalError(err.to_string()))?
        } else {
            format!("{}:{}", discovery.address(), control_port)
                .parse()
                .map_err(|err: AddrParseError| ServiceError::InternalError(err.to_string()))?
        };

        // Run connection in the background
        ControlServer::connect_to_peer(self.state.clone(), socket_addr).await;

        Ok(())
    }

    async fn handle_service_registered(&self) -> Result<(), ServiceError> {
        self.service_sender
            .send(ServiceMessage::ServiceStarted)
            .await
            .map_err(|_| ServiceError::InternalError("async channel closed".to_string()))?;

        Ok(())
    }

    pub async fn handle_request(&mut self, request: ServiceRequest) {
        match request {
            ServiceRequest::InitiateTransfer { peer_id } => {}
            ServiceRequest::SetAuthorizedKeys(keys) => {}
            ServiceRequest::StopService => {}
        }
    }

    pub async fn run(&mut self) -> Result<(), ServiceError> {
        let mut rendezvous_server = rendezvous_server::RendezvousServer::run(0).await.unwrap();
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
        let service = ZeroconfService::run(control_server.port(), my_id, zeroconf_sender.clone());
        let browser = ZeroconfBrowser::run(zeroconf_sender);

        let request_receiver = self.request_receiver.take().unwrap();

        loop {
            println!("Listening for events");
            let mut rendezvous = Box::pin(rendezvous_server.wait_for_connection()).fuse();
            let mut control = Box::pin(control_server.wait_for_connection()).fuse();
            let mut request = Box::pin(request_receiver.recv()).fuse();

            select! {
                msg = zeroconf_receiver.recv().fuse() => if let Ok(msg) = &msg {
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
                msg_res = request => match msg_res {
                    Ok(msg) => {
                    },
                    Err(err) => {

                    }
                },
                () = rendezvous => println!("Rendezvous server stopped"),
                () = control => println!("Control server stopped"),
            }
        }
    }
}
