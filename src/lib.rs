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
        ReaderMessageType, Redis, Uds, InternalIps
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

use futures::{self, AsyncBufReadExt, FutureExt, StreamExt};
use log::*;
use prelude::*;
use std::process::Child;

pub struct Ids<'a, T> {
    readers: Vec<EveReader<T>>,
    process: Option<IdsProcess>,
    ipc_servers: Vec<packet_ipc::ConnectedIpc<'a>>,
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
    pub fn send<'b, T: AsIpcPacket + 'a>(&'a self, packets: &'b [T], server_id: usize) -> Result<usize, Error> {
        let server = self.ipc_servers.get(server_id).ok_or(Error::MissingServerId(server_id))?;
        let packets_sent = packets.len();
        server.send(packets).map_err(Error::PacketIpc)?;
        Ok(packets_sent)
    }

    pub fn close(&mut self) -> Result<(), Error> {
        for server in self.ipc_servers.iter_mut() {
            server.close().map_err(Error::PacketIpc)?
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
        if (args.max_pending_packets as usize) < args.ipc_allocation_batch {
            return Err(Error::Custom {
                msg: "Max pending packets must be larger than IPC allocation batch".into(),
            });
        }
        //need a one shot server name to give to suricata

        debug!("Starting {} IPC servers", args.ipc_servers);
        let servers: Result<Vec<packet_ipc::Server<'a>>, Error> = (0..args.ipc_servers).into_iter().map(|_| {
            let ipc_server_result = packet_ipc::Server::new().map_err(Error::from);
            if let Ok(ref ipc_server) = ipc_server_result {
                debug!("Started IPC server at: {:?}", ipc_server.name());
            } else {
                error!("Failed to start IPC server");
            }
            ipc_server_result
        }).collect();

        let servers = servers?;
        debug!("Begin materialize");
        let config_readers = args.materialize()?;

        let opt_size = args.buffer_size.clone();

        let future_connections: Result<Vec<_>, Error> = config_readers
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
        debug!("Readers are listening, starting suricata");
        let future_connections = future_connections?;
        let server_names = servers.iter().map(|s| s.name().clone()).collect();
        let mut process = Self::spawn_suricata(args, server_names)?;

        /////

        let stdout_complete = {
            let o = process.stdout.take().unwrap();
            let pid = process.id();
            let o = smol::Unblock::new(o);
            let reader = futures::io::BufReader::new(o);
            reader.lines().for_each(move |t| {
                if let Ok(l) = t {
                    debug!("[Suricata ({})] {}", pid, l);
                }
                futures::future::ready(())
            })
        };
        let stderr_complete = {
            let o = process.stderr.take().unwrap();
            let pid = process.id();
            let o = smol::Unblock::new(o);
            let reader = futures::io::BufReader::new(o);
            reader.lines().for_each(move |t| {
                if let Ok(l) = t {
                    error!("[Suricata ({})] {}", pid, l);
                }
                futures::future::ready(())
            })
        };

        let lines = async move {
            futures::select! {
                v = stdout_complete.fuse() => v,
                v = stderr_complete.fuse() => v,
            }

            info!("Suricata closed");
        }
        .boxed();

        smol::spawn(lines).detach();
        let mut connected_ipcs = vec![];
        for server in servers {
            let connected_ipc = smol::block_on(async move { server.accept() })?;
            connected_ipcs.push(connected_ipc);
        }

        debug!("IPC Connection formed");

        let readers = futures::future::join_all(future_connections.into_iter()).await;
        let readers: Result<Vec<_>, Error> = readers.into_iter().collect();

        Ok(Ids {
            readers: readers?,
            process: Some(IdsProcess { inner: process }),
            ipc_servers: connected_ipcs,
        })
    }

    fn spawn_suricata(args: Config, server_names: Vec<String>) -> Result<Child, Error> {
        let mut command = std::process::Command::new(args.exe_path.to_str().unwrap());
        let server_args: Vec<String> = {
            let mut base_args: Vec<String> = vec!["-c",
                                                  args.materialize_config_to.to_str().unwrap(),
                                                  "--set",
                                                  &format!("plugins.0={}", args.ipc_plugin.to_string_lossy()),
                                                  "--capture-plugin=ipc-plugin",
                                                  "--set",
                                                  &format!("ipc.allocation-batch={}", args.ipc_allocation_batch)]
                .into_iter()
                .map(|s|{
                    String::from(s)
                }).collect();

            let concat_server = server_names.join(",");
            let server_args = vec!["--set".to_string(), format!("ipc.server={}", concat_server)];

            // let server_args = server_names
            //     .iter()
            //     .flat_map(|s| {
            //         vec!["--set".to_string(), format!("ipc.server={}", s)].into_iter()
            //     });

            base_args.extend(server_args);
            base_args
        };
        command
            .args(server_args)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped());
        info!("Spawning {:?}", command);
        command.spawn().map_err(Error::Io)
    }
}
