use crate::Error;

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

    pub fn render(&self, materialize_path: &PathBuf) -> Result<String, Error> {
        let path = if let Some(ref p) = self.path {
            p.clone()
        } else {
            let p = materialize_path.join("filestore");
            log::info!("Setting up default filestore path {:?}", p);
            if !p.exists() {
                log::info!("Default filestore path {:?} did not exist", p);
                std::fs::create_dir_all(&p)?;
            }
            p
        };
        let enabled = if self.enabled { "true" } else { "false" };
        let r = RenderedFilestore {
            enabled: enabled,
            path: path.to_string_lossy(),
        };
        r.render().map_err(Error::Askama)
    }
}

#[derive(Template)]
#[template(path = "filestore.yaml.in", escape = "none")]
pub struct RenderedFilestore<'a> {
    enabled: &'a str,
    path: std::borrow::Cow<'a, str>,
}
