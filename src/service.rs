use async_std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use crate::zeroconf::{ZeroconfBrowser, ZeroconfEvent, ZeroconfService};
use futures::{select, FutureExt};
use magic_wormhole_mailbox::{rendezvous_server, RendezvousServer};
use sysinfo::{SystemExt, UserExt};
use zeroconf::prelude::*;
use zeroconf::ServiceDiscovery;
use crate::control::{ControlServer, ControlServerState, ControlServerStateInner, PeerInfo};

pub enum ServiceMessage {
    Started,
    Stopped,
    PeersChanged,
}

fn system_peer_info(my_id: uuid::Uuid) -> PeerInfo {
    let system_info = sysinfo::System::new();

    PeerInfo::new(system_info.host_name().unwrap_or("?".to_string()),
                  my_id.to_string(), None, None)
}

async fn handle_service_discovered(state: ControlServerState, discovery: &ServiceDiscovery) {
    let my_id = &state.read().my_info.session_id.clone();
    let txt = match &discovery.txt() {
        None => return,
        Some(txt) => txt,
    };

    let peer_id = if let Some(id) = txt.get("uuid").as_ref() {
        id.clone()
    } else {
        println!("No uuid specified in mDNS txt record");
        return;
    };

    if &peer_id == my_id {
        println!("Discovered myself");
        return;
    }

    let control_port = if let Some(port) = txt.get("control-port") {
        port
    } else {
        println!("No control-port specified in mDNS txt record");
        return;
    };

    // Connect to the control port
    let socket_addr = if discovery.address().contains(":") {
        // This is an IPv6 address
        // TODO: Is there a better way?
        format!("[{}]:{}", discovery.address(), control_port).parse().unwrap()
    } else {
        format!("{}:{}", discovery.address(), control_port).parse().unwrap()
    };

    if state.read().peers.contains_key(&peer_id) {
        println!("I already know about peer {}, adding address alias", peer_id);
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

pub async fn run() -> Result<(), std::io::Error> {
    let my_id = uuid::Uuid::new_v4();
    let my_peer_info = system_peer_info(my_id);

    let mut mailbox = rendezvous_server::RendezvousServer::run(0)
    .await
        .unwrap();
    println!("Rendezvous: Listening on port: {}", mailbox.port());

    let mut control = ControlServer::run(0, my_peer_info).await?;
    println!("Control: Listening on port: {}", control.port());
    let state = control.state();

    let service = ZeroconfService::run(control.port(), my_id);
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
                            handle_service_discovered(state.clone(), discovery).await;
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
