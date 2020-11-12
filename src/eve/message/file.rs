use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum FileState {
    #[serde(rename = "OPEN")]
    Open,
    #[serde(rename = "CLOSED")]
    Closed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileInfo {
    pub filename: String,
    pub sid: Vec<String>,
    pub gaps: bool,
    pub state: FileState,
    pub stored: bool,
    pub size: usize,
    pub tx_id: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct File {
    #[serde(flatten)]
    pub event_fields: super::EventFields,
    #[serde(rename = "fileinfo")]
    pub info: FileInfo,
}
