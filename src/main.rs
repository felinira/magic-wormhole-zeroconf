#![deny(unused_must_use)]
#![warn(unused_crate_dependencies)]
#![allow(dead_code)]

use crate::key::device::DeviceKeyPair;
use crate::service::ServiceMessage;

mod control;
mod key;
mod network;
mod service;
mod state;
mod zeroconf;

#[async_std::main]
async fn main() {
    let mut service =
        service::Service::new(DeviceKeyPair::generate_new_ed25519(), &service_callback);
    service.run().await.unwrap();
}

fn service_callback(message: ServiceMessage) {
    println!("message received on callback: {:?}", message);
}
