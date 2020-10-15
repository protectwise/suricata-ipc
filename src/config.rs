use crate::errors::Error;

use askama::Template;
use log::debug;
use std::io::Write;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub enum ReaderMessageType {
    Alert,
    Dns,
    Flow,
    Http(HttpConfig),
    Smtp,
    Stats,
    Tls,
}

impl std::fmt::Display for ReaderMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Alert => write!(f, "Alert"),
            Self::Dns => write!(f, "Dns"),
            Self::Flow => write!(f, "Flow"),
            Self::Http(_) => write!(f, "Http"),
            Self::Smtp => write!(f, "Smtp"),
            Self::Stats => write!(f, "Stats"),
            Self::Tls => write!(f, "Tls"),
        }
    }
}

pub struct UdsListener {
    pub listener: std::os::unix::net::UnixListener,
    pub path: std::path::PathBuf,
}

pub enum Listener {
    External,
    Redis,
    Uds(UdsListener),
}

pub struct Reader {
    pub eve: EveConfiguration,
    pub message: ReaderMessageType,
    pub listener: Listener,
}

impl Reader {
    pub fn message(&self) -> &ReaderMessageType {
        &self.message
    }
}

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

#[derive(Clone)]
pub struct ConfigReader {
    pub eve: EveConfiguration,
    pub message: ReaderMessageType,
}

impl ConfigReader {
    pub fn create_reader(&self) -> Result<Reader, Error> {
        match &self.eve {
            EveConfiguration::Uds(uds) => uds_to_reader(uds.clone(), self.message.clone()),
            EveConfiguration::Redis(_) => Ok(Reader {
                eve: self.eve.clone(),
                message: self.message.clone(),
                listener: Listener::Redis,
            }),
            EveConfiguration::Custom(custom) => {
                if let Some(uds) = custom.uds.as_ref() {
                    uds_to_reader(uds.clone(), self.message.clone())
                } else {
                    Ok(Reader {
                        eve: self.eve.clone(),
                        message: self.message.clone(),
                        listener: Listener::External,
                    })
                }
            }
        }
    }
}

#[derive(Template)]
#[template(path = "suricata.yaml.in", escape = "none")]
struct ConfigTemplate<'a> {
    rules: &'a str,
    readers: &'a Vec<ConfigReader>,
    community_id: &'a str,
    suricata_config_path: &'a str,
    internal_ips: &'a InternalIps,
    max_pending_packets: &'a str,
    live: bool,
    default_log_dir: &'a str,
    plugins: &'a Vec<String>,
}

/// Configuration options for redis output
#[derive(Clone)]
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
#[derive(Clone)]
pub struct Uds {
    pub path: PathBuf,
    pub external_listener: bool,
}

impl Default for Uds {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/tmp"),
            external_listener: false,
        }
    }
}

#[derive(Clone)]
pub struct CustomOption {
    pub key: String,
    pub value: String,
}

#[derive(Clone)]
pub struct Custom {
    pub name: String,
    pub options: Vec<CustomOption>,
    pub uds: Option<Uds>,
}

/// Eve configuration
#[derive(Clone)]
pub enum EveConfiguration {
    Redis(Redis),
    Uds(Uds),
    Custom(Custom),
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

#[derive(Clone, Debug)]
pub enum DumpAllHeaders {
    Both,
    Request,
    Response,
}

#[derive(Clone, Debug)]
pub struct HttpConfig {
    pub extended: bool,
    pub custom: Vec<String>,
    pub dump_all_headers: Option<DumpAllHeaders>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            extended: false,
            custom: vec![],
            dump_all_headers: Some(DumpAllHeaders::Both),
        }
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
    /// Additional http configuration options
    pub http_config: HttpConfig,
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
    /// Path where the suricata executable lives
    pub exe_path: PathBuf,
    /// Configuration for eve
    pub eve: EveConfiguration,
    /// Path where the rules reside at
    pub rule_path: PathBuf,
    /// Path where suricata config resides at (e.g. threshold config)
    pub suricata_config_path: PathBuf,
    /// Internal ips to use for HOME_NET
    pub internal_ips: InternalIps,
    /// Max pending packets before suricata will block on incoming packets
    pub max_pending_packets: u16,
    /// Adjust uds buffer size
    pub buffer_size: Option<usize>,
    /// Whether we should use live or offline mode in suricata. Live will use system time for
    /// time related activites in suricata like flow expiration, while offline mode uses packet
    /// time per thread
    pub live: bool,
    /// Directory to use for suricata logging
    pub default_log_dir: PathBuf,
    /// Readers to use (supercedes enable_* properties, http_config)
    pub readers: Vec<ConfigReader>,
    /// Location of plugins to attempt to load
    pub plugins: Vec<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enable_stats: true,
            enable_flows: true,
            enable_dns: false,
            enable_smtp: false,
            enable_http: false,
            http_config: HttpConfig::default(),
            enable_tls: false,
            enable_community_id: true,
            materialize_config_to: PathBuf::from("/etc/suricata/suricata-rs.yaml"),
            exe_path: {
                if let Some(e) = std::env::var_os("SURICATA_EXE").map(|s| PathBuf::from(s)) {
                    e
                } else {
                    PathBuf::from("/usr/local/bin/suricata")
                }
            },
            eve: EveConfiguration::default(),
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
            max_pending_packets: 800,
            buffer_size: None,
            live: true,
            default_log_dir: {
                if let Some(e) = std::env::var_os("SURICATA_LOG_DIR").map(|s| PathBuf::from(s)) {
                    e
                } else {
                    PathBuf::from("/var/log/suricata")
                }
            },
            readers: vec![],
            plugins: vec![],
        }
    }
}

fn uds_to_reader(mut uds: Uds, mt: ReaderMessageType) -> Result<Reader, Error> {
    let path = uds.path;
    let listener = if !uds.external_listener {
        if path.exists() {
            std::fs::remove_file(&path).map_err(Error::from)?;
        }
        debug!("Listening to {:?} for event type {:?}", path, mt);
        let listener = std::os::unix::net::UnixListener::bind(path.clone()).map_err(Error::from)?;
        Listener::Uds(UdsListener {
            listener: listener,
            path: path.clone(),
        })
    } else {
        Listener::External
    };
    uds.path = path;
    Ok(Reader {
        eve: EveConfiguration::Uds(uds),
        listener: listener,
        message: mt,
    })
}

impl Config {
    fn add_if_missing(&self, readers: &mut Vec<ConfigReader>, message_type: ReaderMessageType) {
        let message_type_discriminant = std::mem::discriminant(&message_type);
        if readers
            .iter()
            .find(|r| std::mem::discriminant(&r.message) == message_type_discriminant)
            .is_none()
        {
            let mut eve = self.eve.clone();
            if let EveConfiguration::Uds(uds) = &mut eve {
                uds.path = uds.path.join(format!("{}.socket", message_type));
            }

            readers.push(ConfigReader {
                eve: eve,
                message: message_type,
            });
        }
    }

    pub fn config_readers(&self) -> Vec<ConfigReader> {
        let mut readers = self.readers.iter().map(|r| r.clone()).collect();

        self.add_if_missing(&mut readers, ReaderMessageType::Alert);

        if self.enable_dns {
            self.add_if_missing(&mut readers, ReaderMessageType::Dns);
        }
        if self.enable_flows {
            self.add_if_missing(&mut readers, ReaderMessageType::Flow);
        }
        if self.enable_http {
            self.add_if_missing(
                &mut readers,
                ReaderMessageType::Http(self.http_config.clone()),
            );
        }
        if self.enable_smtp {
            self.add_if_missing(&mut readers, ReaderMessageType::Smtp);
        }
        if self.enable_stats {
            self.add_if_missing(&mut readers, ReaderMessageType::Stats);
        }
        if self.enable_tls {
            self.add_if_missing(&mut readers, ReaderMessageType::Tls);
        }

        readers
    }

    fn render<'a>(&'a self, config_readers: &'a Vec<ConfigReader>) -> Result<String, Error> {
        let rules = self.rule_path.to_string_lossy().to_owned();
        let suricata_config_path = self.suricata_config_path.to_string_lossy().to_owned();
        let default_log_dir = self.default_log_dir.to_string_lossy().to_owned();
        let internal_ips = &self.internal_ips;
        let community_id = if self.enable_community_id {
            "yes"
        } else {
            "no"
        };
        let max_pending_packets = format!("{}", self.max_pending_packets);

        let plugins = self
            .plugins
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();

        let template = ConfigTemplate {
            rules: &rules,
            readers: config_readers,
            community_id: &community_id,
            suricata_config_path: &suricata_config_path,
            internal_ips: internal_ips,
            max_pending_packets: &max_pending_packets,
            live: self.live,
            default_log_dir: &default_log_dir,
            plugins: &plugins,
        };

        debug!("Attempting to render");
        Ok(template.render().map_err(Error::from)?)
    }

    pub fn materialize<'a>(&'a self) -> Result<Vec<ConfigReader>, Error> {
        let config_readers = self.config_readers();
        let rendered = self.render(&config_readers)?;
        debug!("Writing output.yaml to {:?}", self.materialize_config_to);
        let mut f = std::fs::File::create(&self.materialize_config_to).map_err(Error::Io)?;
        f.write(rendered.as_bytes()).map_err(Error::from)?;
        debug!("Output file written");
        Ok(config_readers)
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
            enable_stats: false,
            enable_flows: false,
            readers: readers,
            ..Config::default()
        };

        let config_readers = config.config_readers();

        let rendered = config.render(&config_readers).unwrap();

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
