use serde::{Deserialize, Serialize};

/// https://github.com/OISF/suricata/blob/master/src/util-file.h#L52
/// https://github.com/OISF/suricata/blob/master/src/output-json.c#L156
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum FileState {
    #[serde(rename = "NONE")]
    None,
    #[serde(rename = "OPEN")]
    Open,
    #[serde(rename = "CLOSED")]
    Closed,
    #[serde(rename = "UNKNOWN")]
    Unknown,
    #[serde(rename = "TRUNCATED")]
    Truncated,
    #[serde(rename = "ERROR")]
    Error,
}

impl std::fmt::Display for FileState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::None => "none",
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Unknown => "unknown",
            Self::Truncated => "truncated",
            Self::Error => "error",
        };
        write!(f, "{}", s)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileInfo {
    #[serde(default)]
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
