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
//!     smol::block_on(async move {
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
    pub use super::config::{
        Config, ConfigReader, Custom, CustomOption, DumpAllHeaders, EveConfiguration, HttpConfig,
        ReaderMessageType, Redis, Uds,
    };
    pub use super::errors::Error;
    pub use super::eve::*;
    pub use super::intel::{
        CachedRule, IdsKey, IntelCache, Observable, Observed, Rule, Rules, Tracer,
    };
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

use log::*;
use prelude::*;
use smol::future::{or, FutureExt};
use smol::io::AsyncBufReadExt;
use smol::stream::StreamExt;
use std::time::Duration;

pub struct Ids<'a, T> {
    close_grace_period: Option<Duration>,
    readers: Vec<EveReader<T>>,
    process: Option<IdsProcess>,
    ipc_server: Option<packet_ipc::ConnectedIpc<'a>>,
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

impl<'a, T> Drop for Ids<'a, T> {
    fn drop(&mut self) {
        let _ = self.close();

        let mut process = match std::mem::replace(&mut self.process, None) {
            Some(process) => process,
            None => return,
        };

        // Attempt to close nicely
        let pid = process.inner.id() as _;
        unsafe { libc::kill(pid, libc::SIGTERM) };

        if let Some(close_grace_period) = self.close_grace_period {
            smol::block_on(or(
                smol::unblock(move || {
                    if let Err(e) = process.inner.wait() {
                        error!(
                            "Unexpected error while waiting on suricata process: {:?}",
                            e
                        );
                    }
                }),
                async move {
                    // If process doesn't end during grace period, send it a sigkill
                    smol::Timer::after(close_grace_period).await;
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                },
            ));
        }
    }
}

impl<'a, M> Ids<'a, M> {
    pub fn send<'b, T: AsIpcPacket + 'a>(&'a self, packets: &'b [T]) -> Result<usize, Error> {
        if let Some(ipc_server) = self.ipc_server.as_ref() {
            let packets_sent = packets.len();
            ipc_server.send(packets).map_err(Error::PacketIpc)?;
            Ok(packets_sent)
        } else {
            Err(Error::Custom {
                msg: "Cannot send when Ids already closed.".to_string(),
            })
        }
    }

    pub fn close(&mut self) -> Result<(), Error> {
        if let Some(mut ipc_server) = std::mem::replace(&mut self.ipc_server, None) {
            ipc_server.close()?;
        }
        Ok(())
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

        let config_readers = args.materialize()?;

        let opt_size = args.buffer_size.clone();

        let connection_tasks: Result<Vec<_>, Error> = config_readers
            .iter()
            .flat_map(|c| {
                let reader = match c.create_reader() {
                    Ok(reader) => reader,
                    Err(e) => return Some(Err(e)),
                };

                if let crate::config::Listener::Uds(l) = reader.listener {
                    let message = reader.message;
                    let path = l.path;
                    debug!(
                        "Spawning acceptor for uds connection from suricata for {:?}",
                        path
                    );
                    match smol::Async::new(l.listener).map_err(Error::from) {
                        Err(e) => Some(Err(e)),
                        Ok(listener) => {
                            let f = smol::spawn(async move {
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

        let connection_tasks = connection_tasks?;

        let ipc = format!("--ipc={}", server_name);
        let mut command = std::process::Command::new(args.exe_path.to_str().unwrap());
        command
            .args(&[
                "-c",
                args.materialize_config_to.to_str().unwrap(),
                "i",
                &ipc,
            ])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped());
        info!("Spawning {:?}", command);
        let mut process = command.spawn().map_err(Error::Io)?;

        let stdout_complete = {
            let o = process.stdout.take().unwrap();
            let pid = process.id();
            let o = smol::Unblock::new(o);
            let reader = smol::io::BufReader::new(o);
            reader.lines().for_each(move |t| {
                if let Ok(l) = t {
                    debug!("[Suricata ({})] {}", pid, l);
                }
            })
        };
        let stderr_complete = {
            let o = process.stderr.take().unwrap();
            let pid = process.id();
            let o = smol::Unblock::new(o);
            let reader = smol::io::BufReader::new(o);
            reader.lines().for_each(move |t| {
                if let Ok(l) = t {
                    error!("[Suricata ({})] {}", pid, l);
                }
            })
        };

        let lines = async move {
            or(stdout_complete, stderr_complete).await;

            info!("Suricata closed");
        }
        .boxed();

        smol::spawn(lines).detach();

        let connected_ipc = smol::block_on(async move { server.accept() })?;

        debug!("IPC Connection formed");

        let mut readers = Vec::with_capacity(connection_tasks.len());
        for future_connection in connection_tasks.into_iter() {
            readers.push(future_connection.await?);
        }

        Ok(Ids {
            close_grace_period: args.close_grace_period,
            readers: readers,
            process: Some(IdsProcess { inner: process }),
            ipc_server: Some(connected_ipc),
        })
    }
}
