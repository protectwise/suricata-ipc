use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Tls {
    #[serde(flatten)]
    pub event_fields: super::EventFields,
    pub info: TlsInfo,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TlsInfo {
    pub subject: String,
    pub issuerdn: String,
    pub session_resumed: bool,
    pub serial: String,
    pub fingerprint: String,
    pub sni: String,
    pub version: String,
    pub notbefore: String,
    pub notafter: String,
    pub certificate: String,
    pub chain: String,
    #[serde(default)]
    pub ja3: Option<Ja3>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Ja3 {
    pub hash: String,
    pub data: String,
    pub string: String,
}
