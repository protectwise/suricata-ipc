//! # suricata-rs
//!
//! Provide access to suricata via a library-like interface. Allows packets to be sent to suricata
//! and alerts received.
//!
//! ```rust
//! # use suricata_rs::prelude::*;
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
    pub use super::eve::{EveAlert, EveEventType, EveMessage, EveReader, EveStats};
    pub use super::intel::{CachedRule, IdsKey, IntelCache, Observed, Rule, Rules, Tracer};
    pub use super::Ids;
    pub use packet_ipc::AsIpcPacket;

    pub use chrono;
}

use futures::{self, FutureExt, StreamExt};
use log::*;
use prelude::*;
use std::future::Future;
use std::{path::PathBuf, pin::Pin};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixListener;

pub struct Ids<'a> {
    reader: Option<EveReader>,
    process: Option<IdsProcess>,
    ipc_server: packet_ipc::ConnectedIpc<'a>,
    output: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

unsafe impl<'a> Send for Ids<'a> {}
unsafe impl<'a> Sync for Ids<'a> {}

pub struct IdsProcess {
    pub inner: tokio::process::Child,
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
        if args.alert_path.exists() {
            std::fs::remove_file(&args.alert_path).map_err(Error::Io)?;
        }

        //need a one shot server name to give to suricata
        let server = packet_ipc::Server::new().map_err(Error::PacketIpc)?;
        let server_name = server.name().clone();

        //need an alert socket that suricata can connect to
        let mut uds_listener = UnixListener::bind(args.alert_path.clone()).map_err(Error::Io)?;

        args.materialize()?;

        let ipc = format!("--ipc={}", server_name);
        let mut command = tokio::process::Command::new(args.exe_path.to_str().unwrap());
        command
            .args(&["-c", args.materialize_config_to.to_str().unwrap(), &ipc])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped());
        info!("Spawning {:?}", command);
        let mut process = command.spawn().map_err(Error::Io)?;

        let mut stdout_complete = {
            let o = process.stdout.take().unwrap();
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
            let o = process.stderr.take().unwrap();
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

        let (uds_connection, uds_addr) = uds_listener.accept().await.map_err(Error::Io)?;

        debug!("UDS connection formed from {:?}", uds_addr);

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
