use crate::eve::message::date_format;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AlertFlowInfo {
    #[serde(with = "date_format")]
    pub start: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AlertInfo {
    pub gid: u64,
    pub signature_id: u64,
    pub rev: u32,
    pub severity: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Alert {
    #[serde(flatten)]
    pub event_fields: super::EventFields,
    #[serde(rename = "alert")]
    pub info: AlertInfo,
}
