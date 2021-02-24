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
use packet_ipc::ConnectedIpc;
use prelude::*;
use smol::future::or;
use smol::io::AsyncBufReadExt;
use smol::stream::{Stream, StreamExt};
use smol::Task;
use std::path::PathBuf;
use std::time::Duration;

//const READER_BUFFER_SIZE: usize = 128;

pub struct SpawnContext<'a, M> {
    process: Option<std::process::Child>,
    awaiting_servers: Vec<Task<Result<packet_ipc::ConnectedIpc<'a>, Error>>>,
    awaiting_readers: Vec<Task<Result<EveReader<M>, Error>>>,
}

impl<'a, M: Send + 'static> SpawnContext<'a, M> {
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
    /// A stream with stdout/error from suricata combined in a Result<String, String>
    /// Useful, to watch for completion on startup and to delegate the logging to the caller.
    fn suricata_output_stream(
        process: &mut std::process::Child,
    ) -> impl Stream<Item = Result<Result<String, String>, Error>> {
        let stdout_complete = {
            let o = process.stdout.take().unwrap();
            let o = smol::Unblock::new(o);
            let reader = smol::io::BufReader::new(o);
            reader
                .lines()
                .map(move |t| match t {
                    Ok(l) => Ok(Ok(l)),
                    Err(e) => Err(Error::Io(e)),
                })
                .fuse()
        };
        let stderr_complete = {
            let o = process.stderr.take().unwrap();
            let o = smol::Unblock::new(o);
            let reader = smol::io::BufReader::new(o);
            reader
                .lines()
                .map(move |t| match t {
                    Ok(l) => Ok(Err(l)),
                    Err(e) => Err(Error::Io(e)),
                })
                .fuse()
        };
        smol::stream::or(stdout_complete, stderr_complete).boxed()
    }

    ///
    /// When suricata starts it will want to process rules, before connecting to the ipc sockets or alert sockets.
    /// During this time it is still possible that suricata may not start, so we expose the SpawnContext along side a
    /// Stream. The `SpawnContext` Should not be used by you (you jerk). The Stream however, should be watched for completion
    /// When the Stream completes, you may consider Suricata dead. The streams element is a Result<String, String> representing
    /// stdout, stderr respectively.
    ///
    /// Warning, you MUST consume the `Stream` if you don't Suricata will eventiually lock up.
    /// If you are unsure about any of this use `Ids::new()`
    pub fn new(
        args: &Config,
    ) -> Result<
        (
            SpawnContext<'a, M>,
            impl Stream<Item = Result<Result<String, String>, Error>>,
        ),
        Error,
    > {
        if (args.max_pending_packets as usize) < args.ipc_plugin.allocation_batch_size {
            return Err(Error::Custom {
                msg: "Max pending packets must be larger than IPC allocation batch".into(),
            });
        }
        //let close_grace_period = args.close_grace_period.clone();
        let opt_size = args.buffer_size.clone();

        let awaiting_readers: Vec<_> = args
            .outputs
            .iter()
            .flat_map(|c| connect_output::<M>(c, opt_size.clone()))
            .collect();

        info!("Readers are listening, starting suricata");

        let (ipc_plugin, servers) = args.ipc_plugin.clone().into_plugin()?;
        args.materialize(ipc_plugin)?;

        let awaiting_servers: Vec<Task<Result<ConnectedIpc, Error>>> = servers
            .into_iter()
            .map(|s| smol::spawn(async move { s.accept().map_err(Error::PacketIpc) }))
            .collect();

        let mut process = Self::spawn_suricata(&args)?;
        info!("Spawn complete");

        let output_streams = Self::suricata_output_stream(&mut process);
        let context = SpawnContext {
            process: Some(process),
            awaiting_servers,
            awaiting_readers,
        };
        info!("Return stream and ctx");
        Ok((context, output_streams))
    }
}

impl<'a, T> Drop for SpawnContext<'a, T> {
    fn drop(&mut self) {
        let process = match std::mem::replace(&mut self.process, None) {
            Some(process) => process,
            None => return,
        };
        let pid = process.id() as _;
        // Dont mess around!
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
}

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

    pub async fn new_with_spawn_context(
        args: Config,
        mut spawn_context: SpawnContext<'a, M>,
    ) -> Result<Ids<'a, M>, Error> {
        if (args.max_pending_packets as usize) < args.ipc_plugin.allocation_batch_size {
            return Err(Error::Custom {
                msg: "Max pending packets must be larger than IPC allocation batch".into(),
            });
        }
        let close_grace_period = args.close_grace_period.clone();

        let pending_ipc_connections = std::mem::take(&mut spawn_context.awaiting_servers);
        let awaiting_readers = std::mem::take(&mut spawn_context.awaiting_readers);

        let connected_ipcs = async move {
            let mut ipcs = Vec::with_capacity(pending_ipc_connections.len());
            for ipc in pending_ipc_connections {
                ipcs.push(ipc.await);
            }
            let ipcs: Result<Vec<_>, _> = ipcs.into_iter().collect();
            ipcs
        }
        .await?;

        info!("IPC Connection formed");

        let readers = async move {
            let mut readers = Vec::with_capacity(awaiting_readers.len());
            for connection in awaiting_readers {
                readers.push(connection.await);
            }
            let readers: Result<Vec<_>, _> = readers.into_iter().collect();
            readers
        }
        .await?;

        info!("Eve readers formed.");

        if !readers.is_empty() {
            info!("{} Eve Readers connected", readers.len());
        }

        Ok(Ids {
            close_grace_period: close_grace_period,
            readers: readers,
            process: (&mut spawn_context).process.take(),
            ipc_servers: connected_ipcs,
        })
    }

    pub async fn new(args: Config) -> Result<Ids<'a, M>, Error>
    where
        M: Send + 'static,
    {
        let (spawn_ctx, stdout_stream) = SpawnContext::new(&args)?;
        let pid: u32 = spawn_ctx
            .process
            .as_ref()
            .map(|p| p.id())
            .ok_or(Error::Custom {
                msg: String::from("Missing process."),
            })?;

        let stdout_fut = stdout_stream.for_each(move |r| match r {
            Err(io) => {
                error!("Fatal io Error ({}) {:?}", pid, io)
            }
            Ok(Ok(line)) => {
                debug!("[Suricata ({})] {}", pid, line);
            }
            Ok(Err(line)) => {
                error!("[Suricata ({})] {}", pid, line);
            }
        });
        smol::spawn(stdout_fut).detach();

        info!("SpawnContext created");

        Self::new_with_spawn_context(args, spawn_ctx).await
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
    info!(
        "Spawning acceptor for uds connection from suricata for {:?}",
        path
    );
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    info!("Listening to {:?} for event type {:?}", path, output_type);
    let listener = std::os::unix::net::UnixListener::bind(path.clone()).map_err(Error::from)?;
    let r = match smol::Async::new(listener).map_err(Error::from) {
        Err(e) => smol::spawn(async move { Err(e) }),
        Ok(listener) => smol::spawn(async move {
            listener.accept().await.map_err(Error::from).map(|t| {
                let (uds_connection, uds_addr) = t;

                info!("UDS connection formed from {:?}", uds_addr);

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
