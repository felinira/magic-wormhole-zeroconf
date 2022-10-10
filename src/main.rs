#![deny(unused_must_use)]
#![warn(unused_crate_dependencies)]
#![allow(dead_code)]

mod control;
mod network;
mod service;
mod zeroconf;

#[async_std::main]
async fn main() {
    service::run().await.unwrap();
}
