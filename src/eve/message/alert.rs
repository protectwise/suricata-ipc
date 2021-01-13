use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlertFlowInfo {
    pub pkts_toserver: usize,
    pub pkts_toclient: usize,
    pub bytes_toserver: usize,
    pub bytes_toclient: usize,
    pub start: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlertInfo {
    pub gid: u64,
    pub signature_id: u64,
    pub rev: u32,
    pub severity: u32,
    #[serde(default)]
    pub files: Vec<crate::eve::message::FileInfo>,
    #[serde(default)]
    pub flow: Option<AlertFlowInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Alert {
    #[serde(flatten)]
    pub event_fields: super::EventFields,
    #[serde(rename = "alert")]
    pub info: AlertInfo,
}
