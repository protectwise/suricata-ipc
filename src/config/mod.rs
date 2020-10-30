pub mod eve;
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
}

/// Runmodes for suricata
#[derive(Clone, Debug)]
pub enum Runmode {
    Single,
    AutoFp,
    Workers,
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

    use std::path::Path;

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

    fn get_reader_sections(readers: Vec<ConfigReader>) -> Vec<String> {
        let config = Config {
            ..Config::default()
        };

        let ipc_plugin = IpcPlugin {
            path: PathBuf("/tmp"),
            servers: "ipc-server".to_string(),
            allocation_batch_size: 1_000,
            live: true,
        };

        let rendered = config.render(ipc_plugin).unwrap();

        let mut result = vec![];

        let mut outputs_section: String = rendered
            .chars()
            .skip(rendered.find("outputs:\n").unwrap())
            .collect();

        let eve_log = "  - eve-log:\n";

        match outputs_section.find(eve_log) {
            Some(index) => {
                outputs_section = outputs_section
                    .chars()
                    .skip(index + eve_log.len())
                    .collect()
            }
            None => return result,
        };

        while let Some(split_index) = outputs_section.find(eve_log) {
            result.push(outputs_section.chars().take(split_index).collect());
            outputs_section = outputs_section
                .chars()
                .skip(split_index + eve_log.len())
                .collect();
        }

        result.push(
            outputs_section
                .chars()
                .take(outputs_section.find("  - http-log:").unwrap())
                .collect(),
        );

        result
    }

    fn get_http_section(http_config: HttpConfig) -> String {
        let config = Config {
            enable_http: true,
            http_config: http_config,
            enable_smtp: true,
            ..Config::default()
        };
        let rendered = config.render(&config.config_readers()).unwrap();

        // Start w/ - http: (unique within template)
        let mut http_section: String = rendered
            .chars()
            .skip(rendered.find("- http:").unwrap())
            .collect();

        // End w/ dns segment start
        http_section = http_section
            .chars()
            .take(http_section.find(" - smtp\n").unwrap())
            .collect();

        http_section
    }

    fn get_plugins_section<P: AsRef<Path>>(plugins: Vec<P>) -> Option<String> {
        let config = Config {
            plugins: plugins.into_iter().map(|p| p.as_ref().into()).collect(),
            ..Config::default()
        };
        let rendered = config.render(&config.config_readers()).unwrap();

        let plugins = "plugins:";

        rendered
            .find(plugins)
            .map(|index| index - plugins.len())
            .map(|to_skip| rendered.chars().skip(to_skip).collect())
    }

    #[test]
    fn test_no_readers() {
        let sections = get_reader_sections(vec![]);

        // Alert is always added
        assert_eq!(1, sections.len());
        assert!(sections[0].find("        - alert\n").is_some());
    }

    #[test]
    fn test_alert_redis() {
        let sections = get_reader_sections(vec![ConfigReader {
            eve: EveConfiguration::Redis(Redis::default()),
            message: ReaderMessageType::Alert,
        }]);

        assert_eq!(1, sections.len());
        assert!(sections[0].find("        - alert\n").is_some());
        assert!(sections[0].find("      filetype: redis\n").is_some());
    }

    #[test]
    fn test_alert_uds() {
        let sections = get_reader_sections(vec![ConfigReader {
            eve: EveConfiguration::Uds(Uds::default()),
            message: ReaderMessageType::Alert,
        }]);

        assert_eq!(1, sections.len());
        assert!(sections[0].find("        - alert\n").is_some());
        assert!(sections[0].find("      filetype: unix_stream\n").is_some());
    }

    #[test]
    fn test_alert_custom_non_uds() {
        let sections = get_reader_sections(vec![ConfigReader {
            eve: EveConfiguration::Custom(Custom {
                name: "test-name".to_string(),
                options: vec![CustomOption {
                    key: "test-key".to_string(),
                    value: "test-value".to_string(),
                }],
                uds: None,
            }),
            message: ReaderMessageType::Alert,
        }]);

        assert_eq!(1, sections.len());
        assert!(sections[0].find("        - alert\n").is_some());
        assert!(sections[0].find("      filetype: test-name\n").is_some());
        assert!(sections[0].find("        test-key: test-value\n").is_some());
    }

    #[test]
    fn test_alert_custom_uds() {
        let sections = get_reader_sections(vec![ConfigReader {
            eve: EveConfiguration::Custom(Custom {
                name: "test-name".to_string(),
                options: vec![CustomOption {
                    key: "test-key".to_string(),
                    value: "test-value".to_string(),
                }],
                uds: Some(Uds {
                    path: "/test/path".into(),
                    ..Uds::default()
                }),
            }),
            message: ReaderMessageType::Alert,
        }]);

        assert_eq!(1, sections.len());
        assert!(sections[0].find("        - alert\n").is_some());
        assert!(sections[0].find("      filetype: test-name\n").is_some());
        assert!(sections[0].find("        test-key: test-value\n").is_some());
        assert!(sections[0].find("        filename: /test/path\n").is_some());
    }

    #[test]
    fn test_dns_redis() {
        let sections = get_reader_sections(vec![ConfigReader {
            eve: EveConfiguration::Redis(Redis::default()),
            message: ReaderMessageType::Dns,
        }]);

        assert_eq!(2, sections.len());
        assert!(sections[0].find("        - dns\n").is_some());
        assert!(sections[0].find("      filetype: redis\n").is_some());
        assert!(sections[1].find("        - alert\n").is_some());
        assert!(sections[1].find("      filetype: unix_stream\n").is_some());
    }

    #[test]
    fn test_default_http() {
        let rendered = get_http_section(HttpConfig::default());

        assert_eq!(true, rendered.contains("#extended: yes"));
        assert_eq!(false, rendered.contains(" extended: yes"));

        assert_eq!(
            true,
            rendered.contains("#custom: [Accept-Encoding, Accept-Language, Authorization]")
        );
        assert_eq!(false, rendered.contains(" custom: ["));

        assert_eq!(true, rendered.contains(" dump-all-headers: both"));
        assert_eq!(false, rendered.contains("#dump-all-headers: "));
    }

    #[test]
    fn test_extended_http() {
        let rendered = get_http_section(HttpConfig {
            extended: true,
            ..HttpConfig::default()
        });

        assert_eq!(false, rendered.contains("#extended: yes"));
        assert_eq!(true, rendered.contains(" extended: yes"));

        assert_eq!(
            true,
            rendered.contains("#custom: [Accept-Encoding, Accept-Language, Authorization]")
        );
        assert_eq!(false, rendered.contains(" custom: ["));

        assert_eq!(true, rendered.contains(" dump-all-headers: both"));
        assert_eq!(false, rendered.contains("#dump-all-headers: "));
    }

    #[test]
    fn test_custom_http() {
        let rendered = get_http_section(HttpConfig {
            custom: vec!["Accept-Encoding".to_string(), "Accept-Language".to_string()],
            ..HttpConfig::default()
        });

        assert_eq!(true, rendered.contains("#extended: yes"));
        assert_eq!(false, rendered.contains(" extended: yes"));

        assert_eq!(
            false,
            rendered.contains("#custom: [Accept-Encoding, Accept-Language, Authorization]")
        );
        assert_eq!(
            true,
            rendered.contains(" custom: [Accept-Encoding, Accept-Language]")
        );

        assert_eq!(true, rendered.contains(" dump-all-headers: both"));
        assert_eq!(false, rendered.contains("#dump-all-headers: "));
    }

    #[test]
    fn test_dump_request_http() {
        let rendered = get_http_section(HttpConfig {
            dump_all_headers: Some(DumpAllHeaders::Request),
            ..HttpConfig::default()
        });

        assert_eq!(true, rendered.contains("#extended: yes"));
        assert_eq!(false, rendered.contains(" extended: yes"));

        assert_eq!(
            true,
            rendered.contains("#custom: [Accept-Encoding, Accept-Language, Authorization]")
        );
        assert_eq!(false, rendered.contains(" custom: ["));

        assert_eq!(true, rendered.contains(" dump-all-headers: request"));
        assert_eq!(false, rendered.contains("#dump-all-headers: "));
    }

    #[test]
    fn test_dump_response_http() {
        let rendered = get_http_section(HttpConfig {
            dump_all_headers: Some(DumpAllHeaders::Response),
            ..HttpConfig::default()
        });

        assert_eq!(true, rendered.contains("#extended: yes"));
        assert_eq!(false, rendered.contains(" extended: yes"));

        assert_eq!(
            true,
            rendered.contains("#custom: [Accept-Encoding, Accept-Language, Authorization]")
        );
        assert_eq!(false, rendered.contains(" custom: ["));

        assert_eq!(true, rendered.contains(" dump-all-headers: response"));
        assert_eq!(false, rendered.contains("#dump-all-headers: "));
    }

    #[test]
    fn test_dump_none_http() {
        let rendered = get_http_section(HttpConfig {
            dump_all_headers: None,
            ..HttpConfig::default()
        });

        assert_eq!(true, rendered.contains("#extended: yes"));
        assert_eq!(false, rendered.contains(" extended: yes"));

        assert_eq!(
            true,
            rendered.contains("#custom: [Accept-Encoding, Accept-Language, Authorization]")
        );
        assert_eq!(false, rendered.contains(" custom: ["));

        assert_eq!(false, rendered.contains(" dump-all-headers:"));
        assert_eq!(true, rendered.contains("#dump-all-headers: both"));
    }

    #[test]
    fn test_no_plugins() {
        assert_eq!(None, get_plugins_section::<String>(vec![]));
    }

    #[test]
    fn test_single_plugin() {
        assert!(get_plugins_section(vec!["/test/path"])
            .unwrap()
            .contains("  - /test/path"));
    }

    #[test]
    fn test_two_plugins() {
        let plugins_section = get_plugins_section(vec!["/test/path", "test/path/two"]).unwrap();
        assert!(plugins_section.contains("  - /test/path"));
        assert!(plugins_section.contains("  - test/path/two"));
    }
}
