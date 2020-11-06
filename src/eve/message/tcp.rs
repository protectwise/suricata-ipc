use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Tcp {
    pub tcp_flags: String,
    pub tcp_flags_ts: String,
    pub tcp_flags_tc: String,
    #[serde(default)]
    pub syn: bool,
    #[serde(default)]
    pub rst: bool,
    #[serde(default)]
    pub psh: bool,
    #[serde(default)]
    pub ack: bool,
    #[serde(default)]
    pub ecn: bool,
    #[serde(default)]
    pub cwr: bool,
    #[serde(default)]
    pub fin: bool,
    #[serde(default)]
    pub urg: bool,
}
