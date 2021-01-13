use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Tls {
    #[serde(flatten)]
    pub event_fields: super::EventFields,
    #[serde(rename = "tls")]
    pub info: TlsInfo,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TlsInfo {
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub issuerdn: Option<String>,
    #[serde(default)]
    pub session_resumed: bool,
    #[serde(default)]
    pub serial: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub notbefore: Option<DateTime<Utc>>,
    #[serde(default)]
    pub notafter: Option<DateTime<Utc>>,
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub chain: Vec<String>,
    #[serde(default)]
    pub ja3: Option<Ja3>,
    #[serde(default)]
    pub ja3S: Option<Ja3S>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Ja3 {
    #[serde(default)]
    pub hash: Option<String>,
    #[serde(default)]
    pub string: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Ja3S {
    #[serde(default)]
    pub hash: Option<String>,
    #[serde(default)]
    pub string: Option<String>,
}
