#![deny(unused_must_use)]
#![warn(unused_crate_dependencies)]
#![allow(dead_code)]

mod service;
mod network;
mod zeroconf;
mod control;

#[async_std::main]
async fn main() {
    service::run().await.unwrap();
}