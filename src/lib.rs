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
#[allow(dead_code)]
#[cfg(feature = "protobuf")]
mod serde_helpers;

pub mod prelude {
    pub use super::config::{Config, EveConfiguration, Redis, Uds, InternalIps};
    pub use super::errors::Error;
    pub use super::eve::*;
    pub use super::intel::{CachedRule, IdsKey, IntelCache, Observed, Rule, Rules, Tracer, Observable};
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

//const READER_BUFFER_SIZE: usize = 128;

pub struct Ids<'a, T> {
    reader: Option<EveReader<T>>,
    process: Option<IdsProcess>,
    ipc_server: packet_ipc::ConnectedIpc<'a>,
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
    pub fn send<'b, T: AsIpcPacket + 'a>(&'a self, packets: &'b [T]) -> Result<usize, Error> {
        let packets_sent = packets.len();
        self.ipc_server.send(packets).map_err(Error::PacketIpc)?;
        Ok(packets_sent)
    }

    pub fn close(&mut self) -> Result<(), Error> {
        self.ipc_server.close().map_err(Error::PacketIpc)
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
        //need a one shot server name to give to suricata
        let server = packet_ipc::Server::new().map_err(Error::from)?;
        let server_name = server.name().clone();

        let listener_and_path = if let EveConfiguration::Uds(uds) = &args.eve {
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



        let mut command = std::process::Command::new(args.exe_path.to_str().unwrap());
        command
            .args(&[
                "-c",
                args.materialize_config_to.to_str().unwrap(),
                "--set",
                &format!("plugins.0={}", args.ipc_plugin.to_string_lossy()),
                "--capture-plugin=ipc-plugin",
                "--set",
                &format!("ipc.server={}", server_name),
                "--set",
                &format!("ipc.allocation-batch={}", args.ipc_allocation_batch),

            ])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped());
        info!("Spawning {:?}", command);
        let mut process = command.spawn().map_err(Error::Io)?;

        let mut stdout_complete = {
            let o = process.stdout.take().unwrap();
            let pid = process.id();
            let reader = futures::io::BufReader::new(smol::reader(o));
            reader
                .lines()
                .for_each(move |t| {
                    if let Ok(l) = t {
                        debug!("[Suricata ({})] {}", pid, l);
                    }
                    futures::future::ready(())
                })
                .fuse()
        };

        let mut stderr_complete = {
            let o = process.stderr.take().unwrap();
            let pid = process.id();
            let reader = futures::io::BufReader::new(smol::reader(o));
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

        smol::Task::blocking(lines).detach();

        debug!("Logging started");

        let connected_ipc = smol::Task::blocking(async move { server.accept() }).await?;

        debug!("IPC Connection formed");

        let (future_connection, path) = if let Some((uds_listener, path)) = listener_and_path {
            debug!("Spawning acceptor for uds connection from suricata");

            let listener = smol::Async::new(uds_listener).map_err(Error::from)?;
            let f = smol::Task::blocking(async move { listener.accept().await });

            (Some(f), Some(path))
        } else {
            (None, None)
        };

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
            ipc_server: connected_ipc,
        })
    }
}
