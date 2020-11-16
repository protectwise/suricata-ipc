use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum FileState {
    #[serde(rename = "OPEN")]
    Open,
    #[serde(rename = "CLOSED")]
    Closed,
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileInfo {
    pub filename: String,
    pub sid: Vec<usize>,
    pub gaps: bool,
    pub state: FileState,
    pub stored: bool,
    pub size: usize,
    pub tx_id: usize,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct File {
    #[serde(flatten)]
    pub event_fields: super::EventFields,
    #[serde(rename = "fileinfo")]
    pub info: FileInfo,
}
