#![deny(unused_must_use)]
#![warn(unused_crate_dependencies)]
#![allow(dead_code)]

mod control;
mod key;
mod network;
mod service;
mod zeroconf;

#[async_std::main]
async fn main() {
    let mut service = service::Service::new();
    service.run().await.unwrap();
}
