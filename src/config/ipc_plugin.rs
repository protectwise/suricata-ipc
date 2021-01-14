use crate::config::plugin::Plugin;
use crate::Error;
use askama::Template;
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct IpcPluginConfig {
    pub path: PathBuf,
    pub allocation_batch_size: usize,
    pub servers: usize,
    pub live: bool,
    pub ipc_to_suricata_channel_size: usize,
}

impl Default for IpcPluginConfig {
    fn default() -> Self {
        let p = if let Ok(p) = std::env::var("SURICATA_IPC_PLUGIN") {
            PathBuf::from(p)
        } else {
            PathBuf::from("/usr/lib/ipc-plugin.so")
        };
        Self::new(p)
    }
}

impl IpcPluginConfig {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path: path,
            allocation_batch_size: 1_000,
            servers: 1,
            live: true,
            ipc_to_suricata_channel_size: 1,
        }
    }

    pub fn into_plugin(self) -> Result<(IpcPlugin, Vec<packet_ipc::Server>), Error> {
        let mut names = Vec::with_capacity(self.servers);
        let mut servers = Vec::with_capacity(self.servers);
        for _ in 0..self.servers {
            let server = packet_ipc::Server::new().map_err(Error::from)?;
            let server_name = server.name().clone();
            names.push(server_name);
            servers.push(server);
        }
        let names = names.join(",");
        let plugin = IpcPlugin {
            path: self.path,
            allocation_batch_size: self.allocation_batch_size,
            servers: names,
            live: self.live,
            ipc_to_suricata_channel_size: self.ipc_to_suricata_channel_size,
        };
        Ok((plugin, servers))
    }
}

#[derive(Template)]
#[template(path = "ipc-plugin.yaml.in", escape = "none")]
pub struct IpcPlugin {
    pub path: PathBuf,
    pub allocation_batch_size: usize,
    pub servers: String,
    pub live: bool,
    pub ipc_to_suricata_channel_size: usize,
}

impl Plugin for IpcPlugin {
    fn name(&self) -> &str {
        "ipc-plugin"
    }
    fn path(&self) -> &Path {
        self.path.as_path()
    }
    fn config(&self) -> Option<String> {
        Some(self.render().unwrap())
    }
}
