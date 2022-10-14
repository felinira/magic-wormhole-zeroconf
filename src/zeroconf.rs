use std::any::Any;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time;
use std::time::Duration;
use zeroconf::prelude::*;
use zeroconf::{
    MdnsBrowser, MdnsService, ServiceDiscovery, ServiceRegistration, ServiceType, TxtRecord,
};

const SERVICE_NAME: &str = "app-drey-Warp-zeroconf-v0";

#[derive(Debug)]
pub(crate) enum ZeroconfEvent {
    Error(zeroconf::error::Error),
    ServiceRegistered,
    ServiceDiscovered(ZeroconfServiceDiscovery),
}

/// ServiceDiscovery is not Sync
#[derive(Debug)]
pub struct ZeroconfServiceDiscovery {
    pub name: String,
    pub service_type: ServiceType,
    pub domain: String,
    pub host_name: String,
    pub address: String,
    pub port: u16,
    pub txt: Option<HashMap<String, String>>,
}

impl From<ServiceDiscovery> for ZeroconfServiceDiscovery {
    fn from(discovery: ServiceDiscovery) -> Self {
        let txt = discovery.txt().as_ref().map(|txt| txt.iter().collect());

        Self {
            name: discovery.name().clone(),
            service_type: discovery.service_type().clone(),
            domain: discovery.domain().clone(),
            host_name: discovery.host_name().clone(),
            address: discovery.address().clone(),
            port: *discovery.port(),
            txt,
        }
    }
}

pub(crate) struct ZeroconfRunner {
    thread: std::thread::JoinHandle<()>,
    stop_handle: Arc<AtomicBool>,
}

impl ZeroconfRunner {
    pub fn stop(self) {
        self.stop_handle.store(true, Ordering::Relaxed);
    }
}

pub(crate) struct ZeroconfService {
    pub runner: ZeroconfRunner,
}

impl ZeroconfService {
    pub fn spawn(
        control_port: u16,
        service_uuid: String,
        sender: async_channel::Sender<ZeroconfEvent>,
    ) -> Self {
        log::info!("Running zeroconf service");
        let stop_handle: Arc<AtomicBool> = Arc::default();
        let stop_handle_thread = stop_handle.clone();
        let thread = std::thread::spawn(move || {
            let mut service =
                MdnsService::new(ServiceType::new(SERVICE_NAME, "tcp").unwrap(), control_port);
            let mut txt_record = TxtRecord::new();

            txt_record.insert("uuid", &service_uuid).unwrap();

            service.set_registered_callback(Box::new(Self::on_service_registered));
            service.set_context(Box::new(sender));
            service.set_txt_record(txt_record);

            let event_loop = service.register().unwrap();

            while !stop_handle_thread.load(Ordering::Relaxed) {
                event_loop.poll(Duration::from_secs(2)).unwrap();
                std::thread::sleep(time::Duration::from_millis(500));
            }
        });

        Self {
            runner: ZeroconfRunner {
                thread,
                stop_handle,
            },
        }
    }

    fn on_service_registered(
        result: zeroconf::Result<ServiceRegistration>,
        context: Option<Arc<dyn Any>>,
    ) {
        let context = context.unwrap();
        let sender = context
            .downcast_ref::<async_channel::Sender<ZeroconfEvent>>()
            .unwrap();

        match result {
            Ok(service) => {
                log::debug!("Service registered: {:?}", service);
                sender
                    .send_blocking(ZeroconfEvent::ServiceRegistered)
                    .unwrap();
            }
            Err(error) => {
                log::error!("Error registering service: {}", error);
                sender.send_blocking(ZeroconfEvent::Error(error)).unwrap();
            }
        }
    }
}

pub(crate) struct ZeroconfBrowser {
    pub runner: ZeroconfRunner,
}

impl ZeroconfBrowser {
    pub fn spawn(sender: async_channel::Sender<ZeroconfEvent>) -> Self {
        log::info!("Running zeroconf listener");
        let stop_handle: Arc<AtomicBool> = Arc::default();
        let stop_handle_thread = stop_handle.clone();
        let thread = std::thread::spawn(move || {
            let mut browser = MdnsBrowser::new(ServiceType::new(SERVICE_NAME, "tcp").unwrap());
            browser.set_service_discovered_callback(Box::new(Self::on_service_discovered));
            browser.set_context(Box::new(sender));
            let event_loop = browser.browse_services().unwrap();

            while !stop_handle_thread.load(Ordering::Relaxed) {
                event_loop.poll(Duration::from_secs(2)).unwrap();
                std::thread::sleep(time::Duration::from_millis(500));
            }
        });

        Self {
            runner: ZeroconfRunner {
                thread,
                stop_handle,
            },
        }
    }

    fn on_service_discovered(
        result: zeroconf::Result<ServiceDiscovery>,
        context: Option<Arc<dyn Any>>,
    ) {
        let context = context.unwrap();
        let sender = context
            .downcast_ref::<async_channel::Sender<ZeroconfEvent>>()
            .unwrap();

        match result {
            Ok(service) => {
                if service.service_type().name() != SERVICE_NAME {
                    return;
                }

                let txt = match service.txt() {
                    None => return,
                    Some(txt) => txt,
                };

                if !txt.contains_key("uuid") {
                    return;
                }

                log::debug!("Service discovered: {:?}", service);
                sender
                    .send_blocking(ZeroconfEvent::ServiceDiscovered(service.into()))
                    .unwrap();
            }
            Err(err) => {
                log::error!("Error: {}", err);
            }
        }
    }
}
