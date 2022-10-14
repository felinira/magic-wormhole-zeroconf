#![deny(unused_must_use)]
#![warn(unused_crate_dependencies)]
#![allow(dead_code)]

use crate::key::device::DeviceKeyPair;
use crate::service::{ServiceMessage, ServiceRequest};

mod control;
mod key;
mod network;
mod service;
mod state;
mod zeroconf;

#[async_std::main]
async fn main() {
    let (request_sender, service_receiver, mut service) =
        service::Service::new(DeviceKeyPair::generate_new_ed25519());
    async_std::task::spawn(async move {
        service.run().await.unwrap();
    });

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
                request_sender
                    .send(ServiceRequest::InitiateTransfer { peer_id })
                    .await
                    .unwrap();
            }
            ServiceMessage::PeerRemoved { peer_id } => {
                println!("Peer removed: {}", peer_id);
            }
            ServiceMessage::RequestInitiateTransfer { peer_id } => {
                println!("Peer requested to initiate a transfer: {}", peer_id);
            }
            ServiceMessage::CompareEmoji {
                peer_id,
                emoji,
                verbose_emoji,
                result_fn,
            } => {
                println!("Please compare these emoji with your peer {}.", peer_id);
                println!("{}", verbose_emoji);
                let mut has_answer = false;
                let mut result = false;

                while !has_answer {
                    print!("Do they match? (y/n) ");

                    let mut user_input = String::new();
                    async_std::io::stdin()
                        .read_line(&mut user_input)
                        .await
                        .unwrap();
                    if user_input.to_lowercase() == "y" {
                        result = true;
                        has_answer = true;
                    } else if user_input.to_lowercase() == "n" {
                        result = false;
                        has_answer = true;
                    } else {
                        has_answer = false;
                    }
                }

                println!("Result {}", result);

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
        }
    }
}

fn service_callback(message: ServiceMessage) {
    //println!("message received on callback: {:?}", message);
}
