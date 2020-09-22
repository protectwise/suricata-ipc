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
//!         let readers: Vec<EveReader<EveMessage>> = ids.take_readers();
//!         let readers = futures::stream::select_all(readers.into_iter());
//!
//!         let packets: Vec<Packet> = vec![];
//!         ids.send(packets.as_slice()).expect("Failed to send packets");
//!
//!         let alerts: Result<Vec<_>, Error> = readers.try_collect().await;
//!         let alerts = alerts.expect("Failed to parse alerts");
//!
//!         for eve_msgs in alerts {
//!             for eve in eve_msgs {
//!                 println!("Eve={:?}", eve);
//!                 if let Some(intel) = cache.observed(eve) {
//!                     if let Observed::Alert { rule, message: _, ts: _} = intel {
//!                         println!("Rule={:?}", rule);
//!                     }
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
    pub use super::config::{Config, DumpAllHeaders, EveConfiguration, HttpConfig, Redis, Uds};
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

pub struct Ids<'a, T> {
    readers: Vec<EveReader<T>>,
    process: Option<IdsProcess>,
    ipc_server: packet_ipc::ConnectedIpc<'a>,
}

unsafe impl<'a, T> Send for Ids<'a, T> {}
unsafe impl<'a, T> Sync for Ids<'a, T> {}

pub struct IdsProcess {
    pub inner: std::process::Child,
}

impl Drop for IdsProcess {
    fn drop(&mut self) {
        if let Err(e) = self.inner.kill() {
            error!("Failed to stop suricata process: {:?}", e);
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

    pub fn take_readers(&mut self) -> Vec<EveReader<M>> {
        std::mem::replace(&mut self.readers, vec![])
    }

    pub fn reload_rules(&self) -> bool {
        if let Some(ref p) = self.process {
            unsafe { libc::kill(p.inner.id() as _, libc::SIGUSR2) == 0 }
        } else {
            false
        }
    }

    pub async fn new(args: Config) -> Result<Ids<'a, M>, Error>
    where
        M: Send + 'static,
    {
        //need a one shot server name to give to suricata
        let server = packet_ipc::Server::new().map_err(Error::from)?;
        let server_name = server.name().clone();

        let readers = args.readers()?;

        args.materialize(readers.iter())?;

        let opt_size = args.buffer_size.clone();

        let future_connections: Result<Vec<_>, Error> = readers
            .into_iter()
            .flat_map(|r| {
                if let crate::config::Listener::Uds(l) = r.listener {
                    let message = r.message;
                    let path = l.path;
                    debug!(
                        "Spawning acceptor for uds connection from suricata for {:?}",
                        path
                    );
                    match smol::Async::new(l.listener).map_err(Error::from) {
                        Err(e) => Some(Err(e)),
                        Ok(listener) => {
                            let f = smol::Task::spawn(async move {
                                listener.accept().await.map_err(Error::from).map(|t| {
                                    let (uds_connection, uds_addr) = t;

                                    debug!("UDS connection formed from {:?}", uds_addr);

                                    if let Some(sz) = opt_size {
                                        EveReader::with_capacity(path, message, uds_connection, sz)
                                    } else {
                                        EveReader::new(path, message, uds_connection)
                                    }
                                })
                            });
                            Some(Ok(f))
                        }
                    }
                } else {
                    None
                }
            })
            .collect();
        let future_connections = future_connections?;

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

        smol::Task::spawn(lines).detach();

        let connected_ipc = smol::Task::blocking(async move { server.accept() }).await?;

        debug!("IPC Connection formed");

        let readers = futures::future::join_all(future_connections.into_iter()).await;
        let readers: Result<Vec<_>, Error> = readers.into_iter().collect();

        Ok(Ids {
            readers: readers?,
            process: Some(IdsProcess { inner: process }),
            ipc_server: connected_ipc,
        })
    }
}
