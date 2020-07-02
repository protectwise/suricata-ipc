//! # suricata-rs
//!
//! Provide access to suricata via a library-like interface. Allows packets to be sent to suricata
//! and alerts received.
//!
//! ```rust,norun
//! # use suricata_ipc::prelude::*;
//! # use futures::TryStreamExt;
//! # use std::path::PathBuf;
//!
//! struct Packet {
//!     data: Vec<u8>,
//!     timestamp: std::time::SystemTime,
//! }
//!
//! impl AsIpcPacket for Packet {
//!     fn timestamp(&self) -> &std::time::SystemTime {
//!         &self.timestamp
//!     }
//!     fn data(&self) -> &[u8] {
//!         self.data.as_slice()
//!     }
//! }
//!
//! fn main() {
//!     let resources = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
//!         .join("resources");
//!     let config = Config::default();
//!     let rules = Rules::from_path(resources.join("test.rules")).expect("Could not parse rules");
//!     let cache: IntelCache<Rule> = rules.into();
//!     cache.materialize_rules(config.rule_path.clone()).expect("Failed to materialize rules");
//!
//!     smol::run(async move {
//!         let mut ids = Ids::new(config).await.expect("Failed to create ids");
//!         let ids_alerts = ids.take_messages().expect("No alerts");
//!
//!         let packets: Vec<Packet> = vec![];
//!         ids.send(packets.as_slice()).expect("Failed to send packets");
//!
//!         let alerts: Result<Vec<_>, Error> = ids_alerts.try_collect().await;
//!         let alerts: Result<Vec<_>, Error> = alerts.expect("Failed to receive alerts")
//!             .into_iter().flat_map(|v| v).collect();
//!         let alerts = alerts.expect("Failed to parse alerts");
//!
//!         for eve in alerts {
//!             println!("Eve={:?}", eve);
//!             if let Some(intel) = cache.observed(eve) {
//!                 if let Observed::Alert { rule, message: _, ts: _} = intel {
//!                     println!("Rule={:?}", rule);
//!                 }
//!             }
//!         }
//!     })
//! }
//! ```
#![deny(unused_must_use, unused_imports, bare_trait_objects)]
mod config;
mod errors;
mod eve;
mod intel;

pub mod prelude {
    pub use super::config::{AlertConfiguration, Config, Redis, Uds};
    pub use super::errors::Error;
    pub use super::eve::{EveAlert, EveEventType, EveMessage, EveReader, EveStats};
    pub use super::intel::{CachedRule, IdsKey, IntelCache, Observed, Rule, Rules, Tracer};
    pub use super::Ids;
    pub use packet_ipc::AsIpcPacket;

    pub use chrono;
}

use futures::{self, AsyncBufReadExt, FutureExt, StreamExt};
use log::*;
use prelude::*;
use std::future::Future;
use std::{path::PathBuf, pin::Pin};

pub struct Ids<'a> {
    reader: Option<EveReader>,
    process: Option<IdsProcess>,
    ipc_server: packet_ipc::ConnectedIpc<'a>,
    output: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

unsafe impl<'a> Send for Ids<'a> {}
unsafe impl<'a> Sync for Ids<'a> {}

pub struct IdsProcess {
    pub inner: std::process::Child,
    alert_path: Option<PathBuf>,
}

impl Drop for IdsProcess {
    fn drop(&mut self) {
        if let Err(e) = self.inner.kill() {
            error!("Failed to stop suricata process: {:?}", e);
        }
        if let Some(path) = self.alert_path.take() {
            if path.exists() {
                if let Err(e) = std::fs::remove_file(&path) {
                    error!("Failed to remove alert socket: {:?}", e);
                }
            }
        }
    }
}

impl<'a> Ids<'a> {
    pub fn send<'b, T: AsIpcPacket + 'a>(&'a self, packets: &'b [T]) -> Result<usize, Error> {
        let packets_sent = packets.len();
        self.ipc_server.send(packets).map_err(Error::PacketIpc)?;
        Ok(packets_sent)
    }

    pub fn close(&mut self) -> Result<(), Error> {
        self.ipc_server.close().map_err(Error::PacketIpc)
    }

    pub fn take_output(&mut self) -> Option<Pin<Box<dyn Future<Output = ()> + Send>>> {
        self.output.take()
    }

    pub fn take_messages(&mut self) -> Option<EveReader> {
        self.reader.take()
    }

    pub fn reload_rules(&self) -> bool {
        if let Some(ref p) = self.process {
            unsafe { libc::kill(p.inner.id() as _, libc::SIGUSR2) == 0 }
        } else {
            false
        }
    }

    pub async fn new(args: Config) -> Result<Ids<'a>, Error> {
        //need a one shot server name to give to suricata
        let server = packet_ipc::Server::new().map_err(Error::from)?;
        let server_name = server.name().clone();

        let listener_and_path = if let AlertConfiguration::Uds(uds) = &args.alerts {
            if uds.external_listener {
                None
            } else {
                if uds.path.exists() {
                    std::fs::remove_file(&uds.path).map_err(Error::from)?;
                }
                let listener = std::os::unix::net::UnixListener::bind(uds.path.clone())
                    .map_err(Error::from)?;
                Some((listener, uds.path.clone()))
            }
        } else {
            None
        };

        args.materialize()?;

        let ipc = format!("--ipc={}", server_name);
        let mut command = std::process::Command::new(args.exe_path.to_str().unwrap());
        command
            .args(&["-c", args.materialize_config_to.to_str().unwrap(), &ipc])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped());
        info!("Spawning {:?}", command);
        let mut process = command.spawn().map_err(Error::Io)?;

        let mut stdout_complete = {
            let o = process.stdout.take().unwrap();
            let pid = process.id();
            let reader = futures::io::BufReader::new(smol::Async::new(o).map_err(Error::from)?);
            reader
                .lines()
                .for_each(move |t| {
                    if let Ok(l) = t {
                        info!("[Suricata ({})] {}", pid, l);
                    }
                    futures::future::ready(())
                })
                .fuse()
        };
        let mut stderr_complete = {
            let o = process.stderr.take().unwrap();
            let pid = process.id();
            let reader = futures::io::BufReader::new(smol::Async::new(o).map_err(Error::from)?);
            reader
                .lines()
                .for_each(move |t| {
                    if let Ok(l) = t {
                        error!("[Suricata ({})] {}", pid, l);
                    }
                    futures::future::ready(())
                })
                .fuse()
        };

        let lines = async move {
            futures::select! {
                v = stdout_complete => v,
                v = stderr_complete => v,
            }

            info!("Suricata closed");
        }
        .fuse()
        .boxed();

        let connected_ipc = server.accept().map_err(Error::from)?;

        debug!("IPC Connection formed");

        let (reader, path) = if let Some((uds_listener, path)) = listener_and_path {
            debug!("Waiting on uds connection from suricata");

            let (uds_connection, uds_addr) = smol::Async::new(uds_listener)
                .map_err(Error::from)?
                .accept()
                .await
                .map_err(Error::from)?;

            debug!("UDS connection formed from {:?}", uds_addr);

            (Some(uds_connection.into()), Some(path))
        } else {
            (None, None)
        };

        Ok(Ids {
            reader: reader,
            process: Some(IdsProcess {
                inner: process,
                alert_path: path,
            }),
            ipc_server: connected_ipc,
            output: Some(lines),
        })
    }
}
