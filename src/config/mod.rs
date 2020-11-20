pub mod eve;
pub mod filestore;
pub mod ipc_plugin;
pub mod output;
pub mod plugin;

use crate::errors::Error;
use askama::Template;
use ipc_plugin::{IpcPlugin, IpcPluginConfig};
use log::debug;
use output::Output;
use plugin::Plugin;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

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

struct RenderedOutput {
    connection: String,
    types: String,
}

struct RenderedIpcPlugin<'a> {
    path: std::borrow::Cow<'a, str>,
    config: String,
}

struct RenderedPlugin<'a> {
    path: std::borrow::Cow<'a, str>,
    config: String,
}

#[derive(Template)]
#[template(path = "suricata.yaml.in", escape = "none")]
struct ConfigTemplate<'a> {
    runmode: Runmode,
    rules: &'a str,
    outputs: Vec<RenderedOutput>,
    community_id: &'a str,
    suricata_config_path: &'a str,
    internal_ips: &'a InternalIps,
    max_pending_packets: &'a str,
    default_log_dir: std::borrow::Cow<'a, str>,
    ipc_plugin: RenderedIpcPlugin<'a>,
    plugins: Vec<RenderedPlugin<'a>>,
    detect_profile: DetectProfile,
    async_oneside: bool,
    filestore: &'a str,
}

/// Runmodes for suricata
#[derive(Clone, Debug)]
pub enum Runmode {
    Single,
    AutoFp,
    Workers,
}

/// Detect Profiles
#[derive(Clone, Debug)]
pub enum DetectProfile {
    Low,
    Medium,
    High,
}

impl Default for DetectProfile {
    fn default() -> Self {
        Self::Medium
    }
}

impl std::fmt::Display for DetectProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
        }
    }
}

impl Default for Runmode {
    fn default() -> Self {
        Self::AutoFp
    }
}

impl std::fmt::Display for Runmode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Single => write!(f, "single"),
            Self::AutoFp => write!(f, "autofp"),
            Self::Workers => write!(f, "workers"),
        }
    }
}

/// Configuration options for suricata
pub struct Config {
    /// Runmode to use
    pub runmode: Runmode,
    /// Outputs to connect to suricata
    pub outputs: Vec<Box<dyn Output + Send + Sync>>,
    /// Whether community id should be enabled, defaults to true
    pub enable_community_id: bool,
    /// Path where config will be materialized to
    pub materialize_config_to: PathBuf,
    /// Path where the suricata executable lives, defaults to /usr/bin/suricata, can be overridden
    /// with environment variable SURICATA_EXE
    pub exe_path: PathBuf,
    /// Path where the rules reside at
    pub rule_path: PathBuf,
    /// Path where suricata config resides at (e.g. threshold config), defaults to /etc/suricata,
    /// can be overridden with environment variable SURICATA_CONFIG_DIR
    pub suricata_config_path: PathBuf,
    /// Internal ips to use for HOME_NET
    pub internal_ips: InternalIps,
    /// Max pending packets before suricata will block on incoming packets
    pub max_pending_packets: u16,
    /// Adjust uds buffer size
    pub buffer_size: Option<usize>,
    /// Directory to use for suricata logging
    pub default_log_dir: PathBuf,
    /// Allowed duration before killing suricata process (defaults to None preserve previous behavior)
    pub close_grace_period: Option<Duration>,
    /// IPC plugin
    pub ipc_plugin: IpcPluginConfig,
    /// Plugins to attempt to load
    pub plugins: Vec<Box<dyn Plugin + Send + Sync>>,
    /// Detect profile
    pub detect_profile: DetectProfile,
    /// async-oneside flow handling
    pub async_oneside: bool,
    /// filestore configuration
    pub filestore: filestore::Filestore,
}

impl Default for Config {
    fn default() -> Self {
        let log_dir = if let Ok(s) = std::env::var("SURICATA_LOG_DIR") {
            PathBuf::from(s)
        } else {
            PathBuf::from("/var/log/suricata")
        };
        Config {
            runmode: Runmode::AutoFp,
            outputs: vec![
                Box::new(output::Alert::new(eve::EveConfiguration::uds(
                    log_dir.join("alert.socket"),
                ))),
                Box::new(output::Flow::new(eve::EveConfiguration::uds(
                    log_dir.join("flow.socket"),
                ))),
                Box::new(output::Http::new(eve::EveConfiguration::uds(
                    log_dir.join("http.socket"),
                ))),
                Box::new(output::Dns::new(eve::EveConfiguration::uds(
                    log_dir.join("dns.socket"),
                ))),
                Box::new(output::Stats::new(eve::EveConfiguration::uds(
                    log_dir.join("stats.socket"),
                ))),
            ],
            enable_community_id: true,
            materialize_config_to: PathBuf::from("/etc/suricata/suricata-rs.yaml"),
            exe_path: {
                if let Some(e) = std::env::var_os("SURICATA_EXE").map(PathBuf::from) {
                    e
                } else {
                    PathBuf::from("/usr/local/bin/suricata")
                }
            },
            rule_path: PathBuf::from("/etc/suricata/custom.rules"),
            suricata_config_path: {
                if let Some(e) = std::env::var_os("SURICATA_CONFIG_DIR").map(|s| PathBuf::from(s)) {
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
            max_pending_packets: 2_500,
            buffer_size: None,
            default_log_dir: log_dir,
            ipc_plugin: IpcPluginConfig::default(),
            plugins: vec![],
            close_grace_period: None,
            detect_profile: DetectProfile::Medium,
            async_oneside: false,
            filestore: filestore::Filestore::default(),
        }
    }
}

impl Config {
    fn render<'a>(&'a self, ipc_plugin: IpcPlugin) -> Result<String, Error> {
        let rules = self.rule_path.to_string_lossy().to_owned();
        let suricata_config_path = self.suricata_config_path.to_string_lossy().to_owned();
        let internal_ips = &self.internal_ips;
        let community_id = if self.enable_community_id {
            "yes"
        } else {
            "no"
        };
        let default_log_dir = self.default_log_dir.to_string_lossy();
        let max_pending_packets = format!("{}", self.max_pending_packets);
        let outputs = self
            .outputs
            .iter()
            .map(|o| RenderedOutput {
                connection: o.eve().render(&o.output_type()),
                types: o.render_messages(),
            })
            .collect();
        let plugins = self
            .plugins
            .iter()
            .map(|p| RenderedPlugin {
                path: p.path().to_string_lossy(),
                config: p.config().unwrap_or_else(|| "".into()),
            })
            .collect();
        let filestore = self.filestore.render(&self.default_log_dir)?;

        let template = ConfigTemplate {
            runmode: self.runmode.clone(),
            rules: &rules,
            community_id: &community_id,
            suricata_config_path: &suricata_config_path,
            internal_ips: internal_ips,
            max_pending_packets: &max_pending_packets,
            default_log_dir: default_log_dir,
            outputs: outputs,
            ipc_plugin: RenderedIpcPlugin {
                path: ipc_plugin.path.to_string_lossy(),
                config: ipc_plugin.render().unwrap(),
            },
            plugins: plugins,
            detect_profile: self.detect_profile.clone(),
            async_oneside: self.async_oneside,
            filestore: &filestore,
        };

        debug!("Attempting to render");
        template.render().map_err(Error::from)
    }

    pub fn materialize(&self, ipc_plugin: IpcPlugin) -> Result<(), Error> {
        let rendered = self.render(ipc_plugin)?;
        debug!("Writing output.yaml to {:?}", self.materialize_config_to);
        let mut f = std::fs::File::create(&self.materialize_config_to).map_err(Error::Io)?;
        f.write(rendered.as_bytes()).map_err(Error::from)?;
        debug!("Output file written");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::output::OutputType;
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

    fn ipc_plugin() -> IpcPlugin {
        let cfg = IpcPluginConfig {
            path: PathBuf::from("ipc-plugin.so"),
            allocation_batch_size: 100,
            servers: 1,
            live: true,
        };
        let (plugin, _) = cfg.into_plugin().unwrap();
        plugin
    }

    #[test]
    fn test_alert_redis() {
        let eve_config = || {
            eve::EveConfiguration::Redis(eve::Redis {
                server: "redis://test".into(),
                port: 6379,
            })
        };
        let outputs: Vec<Box<dyn output::Output + Send + Sync>> =
            vec![Box::new(output::Alert::new(eve_config()))];
        let mut cfg = Config::default();
        cfg.outputs = outputs;
        let rendered = cfg.render(ipc_plugin()).unwrap();

        let regex = regex::Regex::new(
            r#"filetype: redis\s*[\r\n]\s*redis:\s*[\r\n](.*[\r\n])*\s*types:\s*[\r\n]\s*- alert"#,
        )
        .unwrap();

        assert!(regex.find(&rendered).is_some());
    }

    #[test]
    fn test_alert_uds() {
        let eve_config = || eve::EveConfiguration::uds(PathBuf::from("test.socket"));
        let outputs: Vec<Box<dyn output::Output + Send + Sync>> =
            vec![Box::new(output::Alert::new(eve_config()))];
        let mut cfg = Config::default();
        cfg.outputs = outputs;
        let rendered = cfg.render(ipc_plugin()).unwrap();

        let regex = regex::Regex::new(
            r#"filetype:\s+unix_stream\s*[\r\n](.*[\r\n])*\s*types:\s*[\r\n]*\s*- alert"#,
        )
        .unwrap();

        assert!(regex.find(&rendered).is_some());
    }

    struct Custom {
        uds: Option<PathBuf>,
    }

    impl eve::Custom for Custom {
        fn name(&self) -> &str {
            "custom"
        }
        fn options(&self, _output_type: &OutputType) -> std::collections::HashMap<String, String> {
            let mut m = std::collections::HashMap::default();
            m.insert("test-name".into(), "test-key".into());
            m
        }
        fn listener(&self, _output_type: &OutputType) -> Option<PathBuf> {
            self.uds.clone()
        }
        fn render(&self, output_type: &OutputType) -> String {
            eve::render_custom(self, output_type)
        }
    }

    #[test]
    fn test_alert_custom_non_uds() {
        let eve_config = || eve::EveConfiguration::Custom(Box::new(Custom { uds: None }));
        let outputs: Vec<Box<dyn output::Output + Send + Sync>> =
            vec![Box::new(output::Alert::new(eve_config()))];
        let mut cfg = Config::default();
        cfg.outputs = outputs;
        let rendered = cfg.render(ipc_plugin()).unwrap();

        let regex = regex::Regex::new(r#"filetype:\s+custom\s*[\r\n]\s*custom:\s*[\r\n]*\s*test-name: test-key\s*[\r\n](.*[\r\n])*\s*types:\s*[\r\n]*\s*- alert"#).unwrap();

        assert!(regex.find(&rendered).is_some());
    }

    #[test]
    fn test_alert_custom_uds() {
        let eve_config = || {
            eve::EveConfiguration::Custom(Box::new(Custom {
                uds: Some(PathBuf::from("test.path")),
            }))
        };
        let outputs: Vec<Box<dyn output::Output + Send + Sync>> =
            vec![Box::new(output::Alert::new(eve_config()))];
        let mut cfg = Config::default();
        cfg.outputs = outputs;
        let rendered = cfg.render(ipc_plugin()).unwrap();

        let regex = regex::Regex::new(r#"filetype:\s+custom\s*[\r\n]\s*custom:\s*[\r\n]\s*filename:\s+test.path\s*[\r\n]\s*test-name: test-key\s*[\r\n](.*[\r\n])*\s*types:\s*[\r\n]*\s*- alert"#).unwrap();

        assert!(regex.find(&rendered).is_some());
    }

    #[test]
    fn test_dns_uds() {
        let eve_config = || eve::EveConfiguration::uds(PathBuf::from("test.socket"));
        let outputs: Vec<Box<dyn output::Output + Send + Sync>> =
            vec![Box::new(output::Dns::new(eve_config()))];
        let mut cfg = Config::default();
        cfg.outputs = outputs;
        let rendered = cfg.render(ipc_plugin()).unwrap();

        let regex = regex::Regex::new(r#"filetype:\s+unix_stream\s*[\r\n]\s*filename: test\.socket.Dns\.socket\s*[\r\n](.*[\r\n])*\s*types:\s*[\r\n]*\s*- dns"#).unwrap();

        assert!(regex.find(&rendered).is_some());
    }

    #[test]
    fn test_default_http() {
        let eve_config = || eve::EveConfiguration::uds(PathBuf::from("test.socket"));
        let outputs: Vec<Box<dyn output::Output + Send + Sync>> =
            vec![Box::new(output::Http::new(eve_config()))];
        let mut cfg = Config::default();
        cfg.outputs = outputs;
        let rendered = cfg.render(ipc_plugin()).unwrap();

        let regex = regex::Regex::new(r#"filetype:\s+unix_stream\s*[\r\n]\s*filename: test\.socket.Http\.socket\s*[\r\n](.*[\r\n])*\s*types:\s*[\r\n]*\s*- http:"#).unwrap();

        assert!(regex.find(&rendered).is_some());
    }

    #[test]
    fn test_custom_http() {
        let eve_config = || eve::EveConfiguration::uds(PathBuf::from("test.socket"));
        let mut http = output::Http::new(eve_config());
        http.extended = true;
        http.custom = vec!["Accept-Encoding".to_string()];
        let outputs: Vec<Box<dyn output::Output + Send + Sync>> = vec![Box::new(http)];
        let mut cfg = Config::default();
        cfg.outputs = outputs;
        let rendered = cfg.render(ipc_plugin()).unwrap();

        let regex = regex::Regex::new(r#"filetype:\s+unix_stream\s*[\r\n]\s*filename: test.socket.Http.socket\s*[\r\n](.*[\r\n])*\s*types:\s*[\r\n]*\s*- http:\s*(.*[\r\n])*\s*extended: yes\s*(.*[\r\n])*\s*custom: \[Accept\-Encoding\]"#).unwrap();

        assert!(regex.find(&rendered).is_some());
    }
}
