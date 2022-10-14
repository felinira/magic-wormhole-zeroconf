use crate::control::message::PeerInfoMessage;
use crate::control::server::Peer;
use crate::key::device::DeviceKeyPair;
use crate::service::ServiceMessage;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub struct ServiceStateInner {
    pub rendezvous_port: u16,
    pub my_info: PeerInfoMessage,
    pub device_key: DeviceKeyPair,
    pub authorized_keys: HashSet<Vec<u8>>,
    pub peers: HashMap<String, Peer>,

    pub service_sender: async_channel::Sender<ServiceMessage>,
}

#[derive(Clone, derive_more::Deref)]
pub struct ServiceState(Arc<RwLock<ServiceStateInner>>);

impl ServiceState {
    pub fn new(
        my_info: PeerInfoMessage,
        device_key: DeviceKeyPair,
        service_sender: async_channel::Sender<ServiceMessage>,
    ) -> Self {
        Self(Arc::new(RwLock::new(ServiceStateInner {
            my_info,
            rendezvous_port: 0,
            authorized_keys: HashSet::new(),
            peers: Default::default(),
            device_key,

            service_sender,
        })))
    }
}
