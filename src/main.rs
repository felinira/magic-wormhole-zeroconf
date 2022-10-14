#![deny(unused_must_use)]
#![warn(unused_crate_dependencies)]
#![allow(dead_code)]

use crate::key::device::DeviceKeyPair;
use crate::service::{ServiceMessage, ServiceRequest};
use futures::AsyncWriteExt;
use std::collections::HashSet;

mod control;
mod key;
mod network;
mod service;
mod state;
mod zeroconf;

#[async_std::main]
async fn main() {
    pretty_env_logger::init();
    let (request_sender, service_receiver, mut service) =
        service::Service::new(DeviceKeyPair::generate_new_ed25519());
    async_std::task::spawn(async move {
        service.run().await.unwrap();
    });

    let mut requested_peers = HashSet::new();

    loop {
        let msg = service_receiver.recv().await.unwrap();
        match msg {
            ServiceMessage::ServiceStarted => {
                println!("Service started")
            }
            ServiceMessage::ServiceStopped => {
                println!("Service stopped")
            }
            ServiceMessage::ServiceError(err) => {
                println!("Service error: {:?}", err);
            }
            ServiceMessage::PeerAddedUpdated { peer_id, peer_info } => {
                println!("Peer added/updated: {}, {:?}", peer_id, peer_info);
                if !requested_peers.contains(&peer_id) {
                    requested_peers.insert(peer_id.clone());
                    request_sender
                        .send(ServiceRequest::InitiateTransfer { peer_id })
                        .await
                        .unwrap();
                }
            }
            ServiceMessage::PeerRemoved { peer_id } => {
                println!("Peer removed: {}", peer_id);
            }
            ServiceMessage::RequestInitiateTransfer { peer_id, result_fn } => {
                println!("Peer requested to initiate a transfer: {}", peer_id);
                let result = ask_y_n("Do you accept?").await;
                result_fn(result);
            }
            ServiceMessage::CompareEmoji {
                peer_id,
                emoji,
                verbose_emoji,
                result_fn,
            } => {
                println!("Please compare these emoji with your peer {}.", peer_id);
                println!("{}", verbose_emoji);
                let result = ask_y_n("Do they match?").await;

                result_fn(result);
            }
            ServiceMessage::CompareEmojiPeerResult { peer_id, result } => {
                if result {
                    println!(
                        "Peer with id {} has successfully authenticated you",
                        peer_id
                    );
                } else {
                    println!("Peer with id {} did not authenticate you", peer_id);
                }
            }
            ServiceMessage::AllocatedWormhole {
                send,
                peer_id,
                peer_addr,
                code,
            } => {
                let role = if send { "sender" } else { "receiver" };
                println!("Will connect to wormhole {code} as {role} on server {peer_addr}");
            }
            ServiceMessage::InitiateTransferResult { peer_id, result } => {
                if result {
                    println!("Peer {} has allowed our transfer request", peer_id)
                } else {
                    println!("Peer {} has denied our transfer request", peer_id)
                }
            }
        }
    }
}

async fn ask_y_n(question: &str) -> bool {
    loop {
        print!("{} (y/n) ", question);
        async_std::io::stdout().flush().await.unwrap();

        let mut user_input = String::new();
        async_std::io::stdin()
            .read_line(&mut user_input)
            .await
            .unwrap();
        let input = user_input.to_lowercase();
        let input = input.trim().clone();
        if input == "y" {
            return true;
        } else if input == "n" {
            return false;
        }
    }
}
