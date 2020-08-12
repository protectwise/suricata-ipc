use crate::errors::Error;

use askama::Template;
use log::debug;
use std::io::Write;
use std::path::PathBuf;

pub struct InternalIps(Vec<String>);

impl InternalIps {
    pub fn new(ips: Vec<String>) -> Self {
        InternalIps(ips)
    }
}

impl std::fmt::Display for InternalIps {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        let ips = &self.0;
        write!(fmt, "{}", ips.join(","))?;
        Ok(())
    }
}

#[derive(Template)]
#[template(path = "suricata.yaml.in", escape = "none")]
struct ConfigTemplate<'a> {
    rules: &'a str,
    eve: &'a EveConfiguration,
    community_id: &'a str,
    suricata_config_path: &'a str,
    internal_ips: &'a InternalIps,
    stats: &'a str,
    flows: bool,
    http: bool,
    dns: bool,
    tls: bool,
    smtp: bool,
    max_pending_packets: &'a str,
    log_dir: std::borrow::Cow<'a, str>,
}

/// Configuration options for redis output
pub struct Redis {
    pub server: String,
    pub port: u16,
}

impl Default for Redis {
    fn default() -> Self {
        Self {
            server: "redis".into(),
            port: 6379,
        }
    }
}

/// Configuration options for Alert socket
pub struct Uds {
    pub path: PathBuf,
    pub external_listener: bool,
}

impl Default for Uds {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/tmp/suricata.alerts"),
            external_listener: false,
        }
    }
}

/// Eve configuration
pub enum EveConfiguration {
    Redis(Redis),
    Uds(Uds),
}

impl EveConfiguration {
    pub fn uds(path: PathBuf) -> Self {
        Self::Uds(Uds {
            path: path,
            external_listener: false,
        })
    }
}

impl Default for EveConfiguration {
    fn default() -> Self {
        Self::Uds(Uds::default())
    }
}

/// Configuration options for suricata
pub struct Config {
    /// Whether statistics should be enabled (output) for suricata, defaults to true
    pub enable_stats: bool,
    /// Whether flows should be enabled (output) for suricata, defaults to true
    pub enable_flows: bool,
    /// Whether http should be enabled (output) for suricata, defaults to false
    pub enable_http: bool,
    /// Whether dns should be enabled (output) for suricata, defaults to false
    pub enable_dns: bool,
    /// Whether smtp should be enabled (output) for suricata, defaults to false
    pub enable_smtp: bool,
    /// Whether tls should be enabled (output) for suricata, defaults to false
    pub enable_tls: bool,
    /// Whether community id should be enabled, defaults to true
    pub enable_community_id: bool,
    /// Path where config will be materialized to
    pub materialize_config_to: PathBuf,
    /// Path where the suricata executable lives, defaults to /usr/bin/suricata, can be overridden
    /// with environment variable SURICATA_EXE
    pub exe_path: PathBuf,
    /// Configuration for eve
    pub eve: EveConfiguration,
    /// Path where the rules reside at
    pub rule_path: PathBuf,
    /// Path where suricata config resides at (e.g. threshold config), defaults to /etc/suricata,
    /// can be overridden with environment variable SURICATA_CONFIG_DIR
    pub suriata_config_path: PathBuf,
    /// Internal ips to use for HOME_NET
    pub internal_ips: InternalIps,
    /// Max pending packets before suricata will block on incoming packets
    pub max_pending_packets: u16,
    /// Path where suricata ipc plugin resides at, defaults to /usr/lib/ipc-plugin.so, can be
    /// overridden with environment variable SURICATA_IPC_PLUGIN
    pub ipc_plugin: PathBuf,
    /// Path to log to, defaults to /var/log/suricata, can be overridden with environment variable
    /// SURICATA_LOG_DIR
    pub log_dir: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enable_stats: true,
            enable_flows: true,
            enable_dns: false,
            enable_smtp: false,
            enable_http: false,
            enable_tls: false,
            enable_community_id: true,
            materialize_config_to: PathBuf::from("/etc/suricata/suricata-rs.yaml"),
            exe_path: {
                if let Some(e) = std::env::var_os("SURICATA_EXE").map(PathBuf::from) {
                    e
                } else {
                    PathBuf::from("/usr/local/bin/suricata")
                }
            },
            eve: EveConfiguration::default(),
            rule_path: PathBuf::from("/etc/suricata/custom.rules"),
            suriata_config_path: {
                if let Some(e) = std::env::var_os("SURICATA_CONFIG_DIR").map(PathBuf::from) {
                    e
                } else {
                    PathBuf::from("/etc/suricata")
                }
            },
            internal_ips: InternalIps(vec![
                String::from("10.0.0.0/8,172.16.0.0/12"),
                String::from("e80:0:0:0:0:0:0:0/64"),
                String::from("127.0.0.1/32"),
                String::from("fc00:0:0:0:0:0:0:0/7"),
                String::from("192.168.0.0/16"),
                String::from("169.254.0.0/16"),
            ]),
            max_pending_packets: 800,
            ipc_plugin: {
                if let Some(e) = std::env::var_os("SURICATA_IPC_PLUGIN").map(PathBuf::from) {
                    e
                } else {
                    PathBuf::from("/usr/lib/ipc-plugin.so")
                }
            },
            log_dir: {
                if let Some(e) = std::env::var_os("SURICATA_LOG_DIR").map(PathBuf::from) {
                    e
                } else {
                    PathBuf::from("/var/log/suricata")
                }
            },
        }
    }
}

impl Config {
    pub fn materialize(&self) -> Result<(), Error> {
        let rules = self.rule_path.to_string_lossy().to_owned();
        let suricata_config_path = self.suriata_config_path.to_string_lossy().to_owned();
        let internal_ips = &self.internal_ips;
        let stats = if self.enable_stats { "yes" } else { "no" };
        let community_id = if self.enable_community_id {
            "yes"
        } else {
            "no"
        };
        let log_dir = self.log_dir.to_string_lossy();
        let max_pending_packets = format!("{}", self.max_pending_packets);
        let template = ConfigTemplate {
            rules: &rules,
            eve: &self.eve,
            community_id: &community_id,
            suricata_config_path: &suricata_config_path,
            internal_ips: internal_ips,
            stats: &stats,
            flows: self.enable_flows,
            http: self.enable_http,
            dns: self.enable_dns,
            smtp: self.enable_smtp,
            tls: self.enable_tls,
            max_pending_packets: &max_pending_packets,
            log_dir: log_dir,
        };
        debug!("Attempting to render");
        let rendered = template.render().map_err(Error::from)?;
        debug!("Writing output.yaml to {:?}", self.materialize_config_to);
        let mut f = std::fs::File::create(&self.materialize_config_to).map_err(Error::Io)?;
        f.write(rendered.as_bytes()).map_err(Error::from)?;
        debug!("Output file written");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::config::InternalIps;

    #[test]
    fn test_internal_ip_display() {
        let internal_ips = InternalIps(vec![
            "169.254.0.0/16".to_owned(),
            "192.168.0.0/16".to_owned(),
            "fc00:0:0:0:0:0:0:0/7".to_owned(),
            "127.0.0.1/32".to_owned(),
            "10.0.0.0/8".to_owned(),
            "172.16.0.0/12".to_owned(),
        ]);
        assert_eq!(format!("{}", internal_ips), "169.254.0.0/16,192.168.0.0/16,fc00:0:0:0:0:0:0:0/7,127.0.0.1/32,10.0.0.0/8,172.16.0.0/12");
    }
}
