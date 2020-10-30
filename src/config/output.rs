use crate::config::eve::EveConfiguration;
use askama::Template;

#[derive(Clone, Debug)]
pub enum OutputType {
    Alert,
    Dns,
    Flow,
    Http,
    Smtp,
    Stats,
    Tls,
    Other(String),
}

impl std::fmt::Display for OutputType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Alert => write!(f, "Alert"),
            Self::Dns => write!(f, "Dns"),
            Self::Flow => write!(f, "Flow"),
            Self::Http => write!(f, "Http"),
            Self::Smtp => write!(f, "Smtp"),
            Self::Stats => write!(f, "Stats"),
            Self::Tls => write!(f, "Tls"),
            Self::Other(s) => write!(f, "{}", s),
        }
    }
}

pub trait Output {
    fn name(&self) -> &str;
    fn render_messages(&self) -> String;
    fn eve(&self) -> &EveConfiguration;
    fn output_type(&self) -> OutputType;
}

pub struct Alert {
    pub eve: EveConfiguration,
}

impl Alert {
    pub fn new(eve: EveConfiguration) -> Self {
        Self { eve: eve }
    }
}

impl Output for Alert {
    fn name(&self) -> &str {
        "alert"
    }
    fn render_messages(&self) -> String {
        format!("        - {}", self.name())
    }
    fn eve(&self) -> &EveConfiguration {
        &self.eve
    }
    fn output_type(&self) -> OutputType {
        OutputType::Alert
    }
}

pub struct Dns {
    pub eve: EveConfiguration,
}

impl Dns {
    pub fn new(eve: EveConfiguration) -> Self {
        Self { eve: eve }
    }
}

impl Output for Dns {
    fn name(&self) -> &str {
        "dns"
    }
    fn render_messages(&self) -> String {
        format!("        - {}", self.name())
    }
    fn eve(&self) -> &EveConfiguration {
        &self.eve
    }
    fn output_type(&self) -> OutputType {
        OutputType::Dns
    }
}

pub struct Flow {
    pub eve: EveConfiguration,
}

impl Flow {
    pub fn new(eve: EveConfiguration) -> Self {
        Self { eve: eve }
    }
}

impl Output for Flow {
    fn name(&self) -> &str {
        "flow"
    }
    fn render_messages(&self) -> String {
        format!("        - {}", self.name())
    }
    fn eve(&self) -> &EveConfiguration {
        &self.eve
    }
    fn output_type(&self) -> OutputType {
        OutputType::Flow
    }
}

#[derive(Clone, Debug)]
pub enum DumpAllHeaders {
    Both,
    Request,
    Response,
}

#[derive(Template)]
#[template(path = "http.yaml.in", escape = "none")]
pub struct Http {
    pub eve: EveConfiguration,
    pub extended: bool,
    pub custom: Vec<String>,
    pub dump_all_headers: Option<DumpAllHeaders>,
}

impl Output for Http {
    fn name(&self) -> &str {
        "http"
    }
    fn render_messages(&self) -> String {
        self.render().unwrap()
    }
    fn eve(&self) -> &EveConfiguration {
        &self.eve
    }
    fn output_type(&self) -> OutputType {
        OutputType::Http
    }
}

impl Http {
    pub fn new(eve: EveConfiguration) -> Self {
        Self {
            eve: eve,
            extended: false,
            custom: vec![],
            dump_all_headers: Some(DumpAllHeaders::Both),
        }
    }
}

pub struct Smtp {
    pub eve: EveConfiguration,
}

impl Smtp {
    pub fn new(eve: EveConfiguration) -> Self {
        Self { eve: eve }
    }
}

impl Output for Smtp {
    fn name(&self) -> &str {
        "smtp"
    }
    fn render_messages(&self) -> String {
        format!("        - {}", self.name())
    }
    fn eve(&self) -> &EveConfiguration {
        &self.eve
    }
    fn output_type(&self) -> OutputType {
        OutputType::Smtp
    }
}

pub struct Stats {
    eve: EveConfiguration,
}

impl Stats {
    pub fn new(eve: EveConfiguration) -> Self {
        Self { eve: eve }
    }
}

impl Output for Stats {
    fn name(&self) -> &str {
        "stats"
    }
    fn render_messages(&self) -> String {
        format!(
            r#"
        - {}:
            enabled: yes
            totals: yes       # stats for all threads merged together
            threads: no       # per thread stats
            deltas: no        # include delta values
        "#,
            self.name()
        )
    }
    fn eve(&self) -> &EveConfiguration {
        &self.eve
    }
    fn output_type(&self) -> OutputType {
        OutputType::Stats
    }
}

pub struct Tls {
    pub eve: EveConfiguration,
}

impl Tls {
    pub fn new(eve: EveConfiguration) -> Self {
        Self { eve: eve }
    }
}

impl Output for Tls {
    fn name(&self) -> &str {
        "tls"
    }
    fn render_messages(&self) -> String {
        format!("        - {}", self.name())
    }
    fn eve(&self) -> &EveConfiguration {
        &self.eve
    }
    fn output_type(&self) -> OutputType {
        OutputType::Tls
    }
}
