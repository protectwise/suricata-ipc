use askama::Template;
use std::path::PathBuf;

#[derive(Default)]
pub struct Filestore {
    enabled: bool,
    path: Option<PathBuf>,
}

impl Filestore {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self {
            enabled: true,
            path: path,
        }
    }

    pub fn render(&self, materialize_path: &PathBuf) -> String {
        let path = if let Some(ref p) = self.path {
            p.clone()
        } else {
            materialize_path.join("filestore")
        };
        let enabled = if self.enabled { "true" } else { "false" };
        let r = RenderedFilestore {
            enabled: enabled,
            path: path.to_string_lossy(),
        };
        r.render().unwrap()
    }
}

#[derive(Template)]
#[template(path = "filestore.yaml.in", escape = "none")]
pub struct RenderedFilestore<'a> {
    enabled: &'a str,
    path: std::borrow::Cow<'a, str>,
}
