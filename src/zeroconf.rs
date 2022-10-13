use std::any::Any;
use std::sync::Arc;
use std::thread::Thread;
use std::time;
use std::time::Duration;
use zeroconf::prelude::*;
use zeroconf::{
    MdnsBrowser, MdnsService, ServiceDiscovery, ServiceRegistration, ServiceType, TxtRecord,
};

const SERVICE_NAME: &'static str = "app-drey-Warp-zeroconf-v0";

#[derive(Debug)]
pub(crate) enum ZeroconfEvent {
    Error(zeroconf::error::Error),
    ServiceRegistered,
    ServiceDiscovered(ServiceDiscovery),
}

pub(crate) struct ZeroconfRunner {
    pub thread: std::thread::JoinHandle<Thread>,
}

pub(crate) struct ZeroconfService {
    pub runner: ZeroconfRunner,
}

impl ZeroconfService {
    pub fn run(
        control_port: u16,
        service_uuid: String,
        sender: async_channel::Sender<ZeroconfEvent>,
    ) -> Self {
        println!("Running service");
        let thread = std::thread::spawn(move || {
            let mut service =
                MdnsService::new(ServiceType::new(SERVICE_NAME, "tcp").unwrap(), control_port);
            let mut txt_record = TxtRecord::new();

            txt_record.insert("uuid", &service_uuid).unwrap();

            service.set_registered_callback(Box::new(Self::on_service_registered));
            service.set_context(Box::new(sender));
            service.set_txt_record(txt_record);

            let event_loop = service.register().unwrap();

            loop {
                std::thread::sleep(time::Duration::from_secs(1));
                event_loop.poll(Duration::from_secs(0)).unwrap();
            }
        });

        Self {
            runner: ZeroconfRunner { thread },
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
                println!("Service registered: {:?}", service);
                sender
                    .send_blocking(ZeroconfEvent::ServiceRegistered)
                    .unwrap();
            }
            Err(error) => {
                println!("Error registering service: {}", error);
                sender.send_blocking(ZeroconfEvent::Error(error)).unwrap();
            }
        }
    }

    pub fn stop(&mut self) {}
}

pub(crate) struct ZeroconfBrowser {
    pub runner: ZeroconfRunner,
}

impl ZeroconfBrowser {
    pub fn run(sender: async_channel::Sender<ZeroconfEvent>) -> Self {
        println!("Running listener");
        let thread = std::thread::spawn(|| {
            let mut browser = MdnsBrowser::new(ServiceType::new(SERVICE_NAME, "tcp").unwrap());
            browser.set_service_discovered_callback(Box::new(Self::on_service_discovered));
            browser.set_context(Box::new(sender));
            let event_loop = browser.browse_services().unwrap();

            loop {
                std::thread::sleep(time::Duration::from_secs(1));
                event_loop.poll(Duration::from_secs(0)).unwrap();
            }
        });

        Self {
            runner: ZeroconfRunner { thread },
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
                /*
                                if txt.get("uuid") == Some(self.uuid.to_string()) {
                                    println!("Discovered myself");
                                    return;
                                }
                */
                println!("Service discovered: {:?}", service);
                sender
                    .send_blocking(ZeroconfEvent::ServiceDiscovered(service))
                    .unwrap();
            }
            Err(err) => {
                println!("Error: {}", err);
            }
        }
    }
}
