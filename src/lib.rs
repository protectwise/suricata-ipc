//! # Bellini
//!
//! Provide access to suricata via a library-like interface. Allows packets to be sent to suricata
//! and alerts received.
//!
//! ```rust
//! # use bellini::prelude::*;
//! # use futures::TryStreamExt;
//! # use std::path::PathBuf;
//! #[tokio::main]
//! async fn main() {
//!     let resources = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
//!         .parent().expect("Invalid path")
//!         .parent().expect("Invalid path")
//!         .join("resources");
//!     let config = Config::default();
//!     let rules = Rules::from_path(resources.join("test.rules")).expect("Could not parse rules");
//!     let cache: IntelCache<Rule> = rules.into();
//!     cache.materialize_rules(config.rule_path.clone()).expect("Failed to materialize rules");
//!
//!     let mut ids = Ids::new(config).await.expect("Failed to create ids");
//!     let ids_alerts = ids.take_alerts().expect("No alerts");
//!
//!     send_packets(&mut ids).await.expect("Failed to send packets");
//!
//!     let alerts: Result<Vec<_>, Error> = ids_alerts.try_collect().await;
//!     let alerts: Result<Vec<_>, Error> = alerts.expect("Failed to receive alerts")
//!         .into_iter().flat_map(|v| v).collect();
//!     let alerts = alerts.expect("Failed to parse alerts");
//!
//!     for eve in alerts {
//!         println!("Eve={:?}", eve);
//!         if let Some(intel) = cache.observed(eve) {
//!             if let Observed::Alert { rule, message: _ } = intel {
//!                 println!("Rule={:?}", rule);
//!             }
//!         }
//!     }
//! }
//! ```
#![deny(unused_must_use, unused_imports, bare_trait_objects)]
mod config;
mod errors;
mod eve;
mod intel;

pub mod prelude {
    pub use super::config::Config;
    pub use super::errors::Error;
    pub use super::eve::{EveReader, Message as EveMessage};
    pub use super::intel::{CachedRule, IdsKey, IntelCache, Observed, Rule, Rules, Tracer};
    pub use super::Ids;
    pub use packet_ipc::packet::AsIpcPacket;

    pub use chrono;
}

use futures::{self, Future, FutureExt, StreamExt};
use log::*;
use prelude::*;
use std::{path::PathBuf, pin::Pin};
use tokio_io::{AsyncBufReadExt, BufReader};
use tokio_net::uds::UnixListener;

pub struct Ids {
    reader: Option<EveReader>,
    process: Option<IdsProcess>,
    ipc_server: packet_ipc::server::ConnectedIpc,
    output: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

unsafe impl Send for Ids {}
unsafe impl Sync for Ids {}

pub struct IdsProcess {
    pub inner: tokio_net::process::Child,
    alert_path: PathBuf,
}

impl Drop for IdsProcess {
    fn drop(&mut self) {
        if let Err(e) = self.inner.kill() {
            error!("Failed to stop suricata process: {:?}", e);
        }
        if self.alert_path.exists() {
            if let Err(e) = std::fs::remove_file(&self.alert_path) {
                error!("Failed to remove alert socket: {:?}", e);
            }
        }
    }
}

impl Ids {
    pub fn send<T: AsIpcPacket>(&mut self, packets: &[T]) -> Result<usize, Error> {
        let ipc_packets: Result<Vec<_>, Error> = packets
            .iter()
            .map(|p| packet_ipc::packet::IpcPacket::try_from(p).map_err(Error::PacketIpc))
            .collect();
        let ipc_packets = ipc_packets?;
        let packets_sent = ipc_packets.len();
        self.ipc_server
            .send(ipc_packets)
            .map_err(Error::PacketIpc)
            .map(|_| packets_sent)
    }

    pub fn close(&mut self) -> Result<(), Error> {
        self.ipc_server.close().map_err(Error::PacketIpc)
    }

    pub fn take_output(&mut self) -> Option<Pin<Box<dyn Future<Output = ()> + Send>>> {
        self.output.take()
    }

    pub fn take_alerts(&mut self) -> Option<EveReader> {
        self.reader.take()
    }

    pub fn reload_rules(&self) -> bool {
        if let Some(ref p) = self.process {
            unsafe { libc::kill(p.inner.id() as _, libc::SIGUSR2) == 0 }
        } else {
            false
        }
    }

    pub async fn new(args: Config) -> Result<Ids, Error> {
        if args.alert_path.exists() {
            std::fs::remove_file(&args.alert_path).map_err(Error::Io)?;
        }

        //need a one shot server name to give to suricata
        let server = packet_ipc::server::Server::new().map_err(Error::PacketIpc)?;
        let server_name = server.name().clone();

        //need an alert socket that suricata can connect to
        let uds_listener = UnixListener::bind(args.alert_path.clone()).map_err(Error::Io)?;
        let mut incoming_connection = uds_listener.incoming();

        args.materialize()?;

        let ipc = format!("--ipc={}", server_name);
        let mut command = tokio_net::process::Command::new(args.exe_path.to_str().unwrap());
        command
            .args(&["-c", args.materialize_config_to.to_str().unwrap(), &ipc])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped());
        info!("Spawning {:?}", command);
        let mut process = command.spawn().map_err(Error::Io)?;

        let mut stdout_complete = {
            let o = process.stdout().take().unwrap();
            let reader = BufReader::new(o);
            let pid = process.id();
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
            let o = process.stderr().take().unwrap();
            let reader = BufReader::new(o);
            let pid = process.id();
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

        let connected_ipc = server.accept().map_err(Error::PacketIpc)?;

        debug!("IPC Connection formed");

        debug!("Waiting on uds connection from suricata");

        let uds_connection = if let Some(c) = incoming_connection.next().await {
            c.map_err(Error::Io)?
        } else {
            return Err(Error::NoUDSConnection);
        };

        debug!("UDS connection formed from {:?}", uds_connection);

        Ok(Ids {
            reader: Some(uds_connection.into()),
            process: Some(IdsProcess {
                inner: process,
                alert_path: args.alert_path,
            }),
            ipc_server: connected_ipc,
            output: Some(lines),
        })
    }
}
