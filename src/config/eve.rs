use crate::config::output::OutputType;
use askama::Template;
use std::path::PathBuf;

#[derive(Template)]
#[template(path = "redis.yaml.in", escape = "none")]
struct RedisRender<'a> {
    redis: &'a Redis,
}

/// Configuration options for redis output
#[derive(Clone, Debug)]
pub struct Redis {
    pub server: String,
    pub port: u16,
}

impl Redis {
    pub fn render(&self, _output_type: &OutputType) -> String {
        RedisRender { redis: self }.render().unwrap()
    }

    pub fn listener(&self, _output_type: &OutputType) -> Option<PathBuf> {
        None
    }
}

impl Default for Redis {
    fn default() -> Self {
        Self {
            server: "redis".into(),
            port: 6379,
        }
    }
}

#[derive(Clone, Debug, Template)]
#[template(path = "uds.yaml.in", escape = "none")]
struct UdsRender<'a> {
    path: std::borrow::Cow<'a, str>,
}

/// Configuration options for Alert socket
#[derive(Clone, Debug)]
pub struct Uds {
    pub path: PathBuf,
}

impl Uds {
    pub fn render(&self, output_type: &OutputType) -> String {
        UdsRender {
            path: self.socket_name(output_type).to_string_lossy(),
        }
        .render()
        .unwrap()
    }

    pub fn listener(&self, output_type: &OutputType) -> Option<PathBuf> {
        Some(self.socket_name(output_type))
    }

    fn socket_name(&self, output_type: &OutputType) -> PathBuf {
        self.path.join(format!("{}.socket", output_type))
    }
}

#[derive(Clone, Debug, Template)]
#[template(path = "custom.yaml.in", escape = "none")]
struct CustomRenderer<'a> {
    name: &'a str,
    options: &'a std::collections::HashMap<String, String>,
    path: Option<std::borrow::Cow<'a, str>>,
}

pub fn render_custom<T: Custom>(custom: &T, output_type: &OutputType) -> String {
    let listener = custom.listener(output_type);
    let options = custom.options(output_type);
    CustomRenderer {
        name: custom.name(),
        options: &options,
        path: listener.as_ref().map(|p| p.to_string_lossy()),
    }
    .render()
    .unwrap()
}

pub trait Custom {
    fn name(&self) -> &str;
    fn options(&self, output_type: &OutputType) -> std::collections::HashMap<String, String>;
    fn listener(&self, output_type: &OutputType) -> Option<PathBuf>;
    fn render(&self, output_type: &OutputType) -> String;
}

/// Eve configuration
pub enum EveConfiguration {
    Redis(Redis),
    Uds(Uds),
    Custom(Box<dyn Custom + Send + Sync>),
}

impl EveConfiguration {
    pub fn render(&self, output_type: &OutputType) -> String {
        match self {
            Self::Redis(r) => r.render(output_type),
            Self::Uds(u) => u.render(output_type),
            Self::Custom(c) => c.render(output_type),
        }
    }

    pub fn uds(path: PathBuf) -> Self {
        Self::Uds(Uds { path: path })
    }

    pub fn listener(&self, output_type: &OutputType) -> Option<PathBuf> {
        match self {
            Self::Redis(r) => r.listener(output_type),
            Self::Uds(u) => u.listener(output_type),
            Self::Custom(c) => c.listener(output_type),
        }
    }
}
