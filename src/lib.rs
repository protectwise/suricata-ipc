#![deny(unused_must_use, unused_imports, bare_trait_objects)]
pub mod config;
pub mod errors;
pub mod eve;
pub mod intel;

//re-exports
pub use chrono;

pub mod ipc {
    pub use packet_ipc::errors::Error;
    pub use packet_ipc::packet::AsIpcPacket;
    pub use packet_ipc::server::ConnectedIpc as Server;

    pub fn try_from<T: AsIpcPacket>(
        packet: &T,
    ) -> Result<packet_ipc::packet::IpcPacket, super::errors::Error> {
        packet_ipc::packet::IpcPacket::try_from(packet).map_err(super::errors::Error::PacketIpc)
    }
}

use crate::config::Config;
use crate::errors::Error;
use futures::{self, Future, FutureExt, StreamExt};
use log::*;
use std::{path::Path, path::PathBuf, pin::Pin};
use tokio_io::{AsyncBufReadExt, BufReader};
use tokio_net::uds::UnixListener;

pub struct Ids {
    reader: Option<eve::reader::EveReader>,
    process: Option<IdsProcess>,
    ipc_server: Option<ipc::Server>,
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
    pub fn take_output(&mut self) -> Option<Pin<Box<dyn Future<Output = ()> + Send>>> {
        self.output.take()
    }

    pub fn take_ipc_server(&mut self) -> Option<packet_ipc::server::ConnectedIpc> {
        self.ipc_server.take()
    }

    pub fn take_alerts(&mut self) -> Option<eve::reader::EveReader> {
        self.reader.take()
    }

    pub fn reload_rules(&self) -> bool {
        if let Some(ref p) = self.process {
            unsafe { libc::kill(p.inner.id() as _, libc::SIGUSR2) == 0 }
        } else {
            false
        }
    }

    pub async fn new<T: AsRef<Path>>(args: Config<T>) -> Result<Ids, Error> {
        let p = args.alert_path.as_ref().to_path_buf();

        if p.exists() {
            std::fs::remove_file(&p).map_err(Error::Io)?;
        }

        //need a one shot server name to give to suricata
        let server = packet_ipc::server::Server::new().map_err(Error::PacketIpc)?;
        let server_name = server.name().clone();

        //need an alert socket that suricata can connect to
        let uds_listener = UnixListener::bind(p.clone()).map_err(Error::Io)?;
        let mut incoming_connection = uds_listener.incoming();

        args.materialize()?;

        let ipc = format!("--ipc={}", server_name);
        let mut command =
            tokio_net::process::Command::new(args.exe_path.as_ref().to_str().unwrap());
        command
            .args(&[
                "-c",
                args.materialize_config_to.as_ref().to_str().unwrap(),
                &ipc,
            ])
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
                alert_path: p,
            }),
            ipc_server: Some(connected_ipc),
            output: Some(lines),
        })
    }
}
