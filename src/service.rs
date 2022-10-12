use crate::control::message::PeerInfoMessage;
use crate::control::service::{ControlServer, ControlServerState, PeerInfo};
use crate::key;
use crate::zeroconf::{ZeroconfBrowser, ZeroconfEvent, ZeroconfService};
use futures::{select, FutureExt};
use magic_wormhole_mailbox::rendezvous_server;
use std::collections::HashSet;
use sysinfo::SystemExt;
use zeroconf::prelude::*;
use zeroconf::ServiceDiscovery;

/// These messages are sent from the service to the application
#[derive(Clone)]
pub enum ServiceMessage {
    ServiceStarted,
    ServiceStopped,
    PeerAddedUpdated {
        peer_id: String,
        peer_info: PeerInfo,
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
#[derive(Clone)]
pub enum ServiceRequest {
    InitiateTransfer { peer_id: String },
    SetAuthorizedKeys(HashSet<Vec<u8>>),
    StopService,
}

pub struct Service {
    service_sender: async_channel::Sender<ServiceMessage>,
    service_receiver: async_channel::Receiver<ServiceMessage>,

    request_sender: async_channel::Sender<ServiceRequest>,
    request_receiver: async_channel::Receiver<ServiceRequest>,
}

impl Service {
    pub fn new() -> Self {
        let (service_sender, service_receiver) = async_channel::unbounded();
        let (request_sender, request_receiver) = async_channel::unbounded();

        Self {
            service_sender,
            service_receiver,
            request_sender,
            request_receiver,
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

    async fn handle_service_discovered(state: ControlServerState, discovery: &ServiceDiscovery) {
        let my_id = &state.read().my_info.service_uuid.clone();
        let txt = match &discovery.txt() {
            None => return,
            Some(txt) => txt,
        };

        let Some(peer_id) = txt.get("uuid") else {
            println!("No uuid specified in mDNS txt record");
            return;
        };

        if &peer_id == my_id {
            println!("Discovered myself");
            return;
        }

        let Some(mailbox_port) = txt.get("mailbox-port")  else {
            println!("No mailbox-port specified in mDNS txt record");
            return;
        };

        let control_port = discovery.port();

        // Connect to the control port
        let socket_addr = if discovery.address().contains(":") {
            // This is an IPv6 address
            // TODO: Is there a better way?
            format!("[{}]:{}", discovery.address(), control_port)
                .parse()
                .unwrap()
        } else {
            format!("{}:{}", discovery.address(), control_port)
                .parse()
                .unwrap()
        };

        if state.read().peers.contains_key(&peer_id) {
            println!(
                "I already know about peer {}, adding address alias",
                peer_id
            );
            let mut lock = state.write();
            if let Some(peer) = lock.peers.get_mut(&peer_id) {
                peer.socket_addrs.insert(socket_addr);
                println!("Peer: {:?}", peer);
            }

            // This is of course not thread safe, because we are not locking and not updating the
            // HashTable either. But it's better to make it easier in the common case.
            return;
        }

        ControlServer::connect_to_peer(state.clone(), socket_addr).await;
    }

    pub async fn run(&mut self) -> Result<(), std::io::Error> {
        let my_id = uuid::Uuid::new_v4();

        let key_pair = key::device::DeviceKeyPair::generate_new_ed25519();
        let my_peer_info = Self::system_peer_info(my_id.to_string());

        let mut mailbox = rendezvous_server::RendezvousServer::run(0).await.unwrap();
        println!("Rendezvous: Listening on port: {}", mailbox.port());

        let mut control = ControlServer::run(0, mailbox.port(), my_peer_info, key_pair).await?;
        println!("Control: Listening on port: {}", control.port());
        let state = control.state();

        let service = ZeroconfService::run(mailbox.port(), control.port(), my_id);
        let service_receiver = service.runner.receiver.clone();

        let browser = ZeroconfBrowser::run();
        let browser_receiver = browser.runner.receiver.clone();

        loop {
            let mut s = service_receiver.recv().fuse();
            let mut b = browser_receiver.recv().fuse();
            let mut m = Box::pin(mailbox.wait_for_connection()).fuse();
            let mut c = Box::pin(control.wait_for_connection()).fuse();

            select! {
                msg = s => println!("{:?}", msg.unwrap()),
                msg = b => {
                    if let Ok(msg) = &msg {
                        match msg {
                            ZeroconfEvent::ServiceDiscovered(discovery) => {
                                Self::handle_service_discovered(state.clone(), discovery).await;
                            }
                            _ => {
                                todo!()
                            }
                        }
                    }
                },
                () = m => println!("mailbox msg"),
                () = c => println!("Control server stopped"),
            }
        }
    }
}
