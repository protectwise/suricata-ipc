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
pub mod config;
mod errors;
mod eve;
mod intel;
#[allow(dead_code)]
#[cfg(feature = "protobuf")]
mod serde_helpers;

pub mod prelude {
    pub use super::config::Config;
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

use crate::config::output::{Output, OutputType};
use config::Config;
use log::*;
use prelude::*;
use smol::future::{or, FutureExt};
use smol::io::AsyncBufReadExt;
use smol::stream::StreamExt;
use std::path::PathBuf;
use std::time::Duration;

//const READER_BUFFER_SIZE: usize = 128;

pub struct Ids<'a, T> {
    close_grace_period: Option<Duration>,
    readers: Vec<EveReader<T>>,
    process: Option<std::process::Child>,
    ipc_servers: Vec<packet_ipc::ConnectedIpc<'a>>,
}

unsafe impl<'a, T> Send for Ids<'a, T> {}
unsafe impl<'a, T> Sync for Ids<'a, T> {}

impl<'a, T> Drop for Ids<'a, T> {
    fn drop(&mut self) {
        let _ = self.close();

        let mut process = match std::mem::replace(&mut self.process, None) {
            Some(process) => process,
            None => return,
        };

        // Attempt to close nicely
        let pid = process.id() as _;
        unsafe { libc::kill(pid, libc::SIGTERM) };

        if let Some(close_grace_period) = self.close_grace_period {
            smol::block_on(or(
                smol::unblock(move || {
                    if let Err(e) = process.wait() {
                        error!(
                            "Unexpected error while waiting on suricata process: {:?}",
                            e
                        );
                    }
                }),
                async move {
                    // If process doesn't end during grace period, send it a sigkill
                    smol::Timer::after(close_grace_period).await;
                    // We already have a mutable borrow in process.wait(), send signal to pid
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                },
            ));
        } else if let Err(e) = process.kill() {
            error!("Failed to stop suricata process: {:?}", e);
        }
    }
}

impl<'a, M> Ids<'a, M> {
    pub fn send<'b, T: AsIpcPacket + 'a>(
        &'a self,
        packets: &'b [T],
        server_id: usize,
    ) -> Result<usize, Error> {
        if let Some(ipc_server) = self.ipc_servers.get(server_id) {
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
        for mut server in self.ipc_servers.drain(..) {
            server.close().map_err(Error::PacketIpc)?
        }
        Ok(())
    }

    pub fn take_readers(&mut self) -> Vec<EveReader<M>> {
        std::mem::replace(&mut self.readers, vec![])
    }

    pub fn reload_rules(&self) -> bool {
        if let Some(ref p) = self.process {
            unsafe { libc::kill(p.id() as _, libc::SIGUSR2) == 0 }
        } else {
            false
        }
    }

    pub async fn new(args: Config) -> Result<Ids<'a, M>, Error>
    where
        M: Send + 'static,
    {
        if (args.max_pending_packets as usize) < args.ipc_plugin.allocation_batch_size {
            return Err(Error::Custom {
                msg: "Max pending packets must be larger than IPC allocation batch".into(),
            });
        }

        let close_grace_period = args.close_grace_period.clone();
        let opt_size = args.buffer_size.clone();

        let connection_tasks: Vec<_> = args
            .outputs
            .iter()
            .flat_map(|c| connect_output::<M>(c, opt_size.clone()))
            .collect();
        debug!("Readers are listening, starting suricata");

        let (ipc_plugin, servers) = args.ipc_plugin.clone().into_plugin()?;
        //args.materialize(ipc_plugin)?;

        let pending_ipc_connections = servers
            .into_iter()
            .map(|s| smol::spawn(async move { s.accept() }));

        let mut process = Self::spawn_suricata(&args)?;

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

        let connected_ipcs = async move {
            let mut ipcs = Vec::with_capacity(pending_ipc_connections.len());
            for ipc in pending_ipc_connections {
                ipcs.push(ipc.await);
            }
            let ipcs: Result<Vec<_>, _> = ipcs.into_iter().collect();
            ipcs
        }
        .await?;

        debug!("IPC Connection formed");

        let readers = async move {
            let mut readers = Vec::with_capacity(connection_tasks.len());
            for connection in connection_tasks {
                readers.push(connection.await);
            }
            let readers: Result<Vec<_>, _> = readers.into_iter().collect();
            readers
        }
        .await?;

        if !readers.is_empty() {
            debug!("{} Eve Readers connected", readers.len());
        }

        Ok(Ids {
            close_grace_period: close_grace_period,
            readers: readers,
            process: Some(process),
            ipc_servers: connected_ipcs,
        })
    }

    fn spawn_suricata(args: &Config) -> Result<std::process::Child, Error> {
        let mut command = std::process::Command::new(args.exe_path.to_str().unwrap());
        let server_args: Vec<String> = vec![
            "-c",
            args.materialize_config_to.to_str().unwrap(),
            "--capture-plugin=ipc-plugin",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        command
            .args(server_args)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped());
        info!("Spawning {:?}", command);
        command.spawn().map_err(Error::Io)
    }
}

fn connect_output<M: Send + 'static>(
    output: &Box<dyn Output + Send + Sync>,
    opt_size: Option<usize>,
) -> Option<smol::Task<Result<EveReader<M>, Error>>> {
    if let Some(path) = output.eve().listener(&output.output_type()) {
        let r = match connect_uds(path, output.output_type().clone(), opt_size) {
            Err(e) => smol::spawn(async move { Err(e) }),
            Ok(t) => t,
        };
        Some(r)
    } else {
        None
    }
}

fn connect_uds<M: Send + 'static>(
    path: PathBuf,
    output_type: OutputType,
    opt_size: Option<usize>,
) -> Result<smol::Task<Result<EveReader<M>, Error>>, Error> {
    debug!(
        "Spawning acceptor for uds connection from suricata for {:?}",
        path
    );
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    debug!("Listening to {:?} for event type {:?}", path, output_type);
    let listener = std::os::unix::net::UnixListener::bind(path.clone()).map_err(Error::from)?;
    let r = match smol::Async::new(listener).map_err(Error::from) {
        Err(e) => smol::spawn(async move { Err(e) }),
        Ok(listener) => smol::spawn(async move {
            listener.accept().await.map_err(Error::from).map(|t| {
                let (uds_connection, uds_addr) = t;

                debug!("UDS connection formed from {:?}", uds_addr);

                if let Some(sz) = opt_size {
                    EveReader::with_capacity(path, output_type, uds_connection, sz)
                } else {
                    EveReader::new(path, output_type, uds_connection)
                }
            })
        }),
    };
    Ok(r)
}
