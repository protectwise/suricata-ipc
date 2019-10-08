use crate::errors::Error;

use askama::Template;
use log::debug;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct InternalIPs(Vec<String>);

impl InternalIPs {
    pub fn new(ips: Vec<String>) -> Self {
        InternalIPs(ips)
    }
}

impl std::fmt::Display for InternalIPs {
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
    alerts: &'a str,
    internal_ips: &'a InternalIPs,
    stats: &'a str,
    max_pending_packets: &'a str,
}

/// Configuration options for suricata
pub struct Config<T: AsRef<Path>> {
    /// Whether statistics should be enabled (output) for suricata
    pub enable_stats: bool,
    /// Path where config will be materialized to
    pub materialize_config_to: T,
    /// Path where the suricata executable lives
    pub exe_path: T,
    /// Path where the alert socket should reside at
    pub alert_path: T,
    /// Path where the rules reside at
    pub rule_path: T,
    /// Internal ips to use for HOME_NET
    pub internal_ips: InternalIPs,
    /// Max pending packets before suricata will block on incoming packets
    pub max_pending_packets: u16,
}

impl Default for Config<PathBuf> {
    fn default() -> Self {
        Config {
            enable_stats: false,
            materialize_config_to: PathBuf::from("/etc/suricata/pw.yaml"),
            exe_path: {
                if let Some(e) = std::env::var_os("SURICATA_EXE").map(|s| PathBuf::from(s)) {
                    e
                } else {
                    PathBuf::from("/usr/local/bin/suricata")
                }
            },
            alert_path: PathBuf::from("/tmp/suricata.alerts"),
            rule_path: PathBuf::from("/etc/suricata/custom.rules"),
            internal_ips: InternalIPs(vec![
                String::from("10.0.0.0/8,172.16.0.0/12"),
                String::from("e80:0:0:0:0:0:0:0/64"),
                String::from("127.0.0.1/32"),
                String::from("fc00:0:0:0:0:0:0:0/7"),
                String::from("192.168.0.0/16"),
                String::from("169.254.0.0/16"),
            ]),
            max_pending_packets: 800,
        }
    }
}

impl<T: AsRef<Path>> Config<T> {
    pub fn materialize(&self) -> Result<(), Error> {
        let rules = self.rule_path.as_ref().to_string_lossy().to_owned();
        let alerts = self.alert_path.as_ref().to_string_lossy().to_owned();
        let internal_ips = &self.internal_ips;
        let stats = format!("{}", self.enable_stats);
        let max_pending_packets = format!("{}", self.max_pending_packets);
        let template = ConfigTemplate {
            rules: &rules,
            alerts: &alerts,
            internal_ips: internal_ips,
            stats: &stats,
            max_pending_packets: &max_pending_packets,
        };
        debug!("Attempting to render");
        let rendered = template.render().map_err(Error::Askama)?;
        let p = self.materialize_config_to.as_ref();
        debug!("Writing output.yaml to {:?}", p);
        let mut f = std::fs::File::create(p).map_err(Error::Io)?;
        f.write(rendered.as_bytes()).map_err(Error::Io)?;
        debug!("Output file written");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::config::InternalIPs;

    #[test]
    fn test_internal_ip_display() {
        let internal_ips = InternalIPs(vec![
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
