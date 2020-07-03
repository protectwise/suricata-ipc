//! # suricata-rs
//!
//! Provide access to suricata via a library-like interface. Allows packets to be sent to suricata
//! and alerts received.
//!
//! ```rust,no_run
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
//!         let sender = ids.take_sender().expect("No sender");
//!
//!         let packets: Vec<Packet> = vec![];
//!         sender.send(packets.as_slice()).expect("Failed to send packets");
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
#[allow(dead_code)]
#[cfg(feature = "protobuf")]
mod serde_helpers;

pub mod prelude {
    pub use super::config::{AlertConfiguration, Config, Redis, Uds};
    pub use super::errors::Error;
    pub use super::eve::*;
    pub use super::intel::{CachedRule, IdsKey, IntelCache, Observed, Rule, Rules, Tracer};
    #[cfg(feature = "protobuf")]
    pub use super::proto;
    pub use super::Ids;
    pub use packet_ipc::AsIpcPacket;

    pub use chrono;
}

#[cfg(feature = "protobuf")]
pub(crate) use eve::parse_date_time;

#[allow(missing_docs)]
#[cfg(feature = "protobuf")]
pub mod proto {
    tonic::include_proto!("suricata");

    impl crate::intel::Observable for Eve {
        fn timestamp(&self) -> chrono::DateTime<chrono::Utc> {
            self.timestamp
                .clone()
                .map(|ts| {
                    let ts = chrono::NaiveDateTime::from_timestamp(ts.seconds, ts.nanos as _);
                    chrono::DateTime::from_utc(ts, chrono::Utc)
                })
                .unwrap_or_else(|| chrono::Utc::now())
        }

        fn key(&self) -> Option<crate::intel::IdsKey> {
            self.alert.as_ref().map(|a| crate::intel::IdsKey {
                gid: a.gid as _,
                sid: a.signature_id as _,
            })
        }
    }
}

use futures::{self, AsyncBufReadExt, FutureExt, StreamExt};
use log::*;
use prelude::*;
use std::path::PathBuf;

pub struct Ids<'a, T> {
    reader: Option<EveReader<T>>,
    process: Option<IdsProcess>,
    senders: Vec<PacketSender<'a>>,
}

unsafe impl<'a, T> Send for Ids<'a, T> {}
unsafe impl<'a, T> Sync for Ids<'a, T> {}

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

impl<'a, M> Ids<'a, M> {
    pub fn take_sender(&mut self) -> Option<PacketSender<'a>> {
        self.senders.pop()
    }

    pub fn close(&mut self) -> Result<(), Error> {
        for sender in &mut self.senders {
            sender.close()?;
        }
        Ok(())
    }

    pub fn take_messages(&mut self) -> Option<EveReader<M>> {
        self.reader.take()
    }

    pub fn reload_rules(&self) -> bool {
        if let Some(ref p) = self.process {
            unsafe { libc::kill(p.inner.id() as _, libc::SIGUSR2) == 0 }
        } else {
            false
        }
    }

    pub async fn new(args: Config) -> Result<Ids<'a, M>, Error> {
        //need connections to give names to servers
        let servers: Result<Vec<_>, _> = (0..args.connections)
            .map(|_| packet_ipc::Server::new().map_err(Error::from))
            .collect();
        let servers = servers?;

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

        let (future_connection, path) = if let Some((uds_listener, path)) = listener_and_path {
            debug!("Spawning acceptor for uds connection from suricata");

            let listener = smol::Async::new(uds_listener).map_err(Error::from)?;
            let f = smol::Task::spawn(async move { listener.accept().await });

            (Some(f), Some(path))
        } else {
            (None, None)
        };

        let server_names: Vec<_> = servers.iter().map(|s| s.name().clone()).collect();
        let ipc = format!("--ipc={}", server_names.join(","));
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

        smol::Task::spawn(lines).detach();

        let connections = servers
            .into_iter()
            .map(|s| smol::Task::blocking(async move { s.accept() }));
        let connections: Result<Vec<_>, _> = futures::future::join_all(connections)
            .await
            .into_iter()
            .collect();
        let connections = connections?;

        debug!("IPC Connection formed");

        let opt_reader = if let Some(f) = future_connection {
            let (uds_connection, uds_addr) = f.await?;

            debug!("UDS connection formed from {:?}", uds_addr);

            Some(uds_connection.into())
        } else {
            None
        };

        Ok(Ids {
            reader: opt_reader,
            process: Some(IdsProcess {
                inner: process,
                alert_path: path,
            }),
            senders: connections
                .into_iter()
                .map(|c| PacketSender { inner: c })
                .collect(),
        })
    }
}

pub struct PacketSender<'a> {
    inner: packet_ipc::ConnectedIpc<'a>,
}

impl<'a> PacketSender<'a> {
    pub fn send<'b, T: AsIpcPacket + 'a>(&'a self, packets: &'b [T]) -> Result<usize, Error> {
        let packets_sent = packets.len();
        self.inner.send(packets)?;
        Ok(packets_sent)
    }

    pub fn close(&mut self) -> Result<(), Error> {
        self.inner.close().map_err(Error::PacketIpc)
    }
}

unsafe impl<'a> Send for PacketSender<'a> {}
unsafe impl<'a> Sync for PacketSender<'a> {}
