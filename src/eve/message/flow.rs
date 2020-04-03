use crate::eve::message::date_format;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub enum State {
    #[serde(rename = "new")]
    New,
    #[serde(rename = "established")]
    Established,
    #[serde(rename = "closed")]
    Closed,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Tcp {
    tcp_flags: usize,
    syn: bool,
    rst: bool,
    ack: bool,
    state: State,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FlowState {
    pub pkts_toserver: usize,
    pub pkts_toclient: usize,
    pub bytes_toserver: usize,
    pub bytes_toclient: usize,
    #[serde(with = "date_format")]
    pub start: DateTime<Utc>,
    #[serde(with = "date_format")]
    pub end: DateTime<Utc>,
    pub alerted: bool,
    pub state: State,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Flow {
    pub src_ip: std::net::IpAddr,
    pub src_port: u16,
    pub dest_ip: std::net::IpAddr,
    pub dest_port: u16,
    pub proto: String,
    pub app_proto: Option<String>,
    #[serde(rename = "flow")]
    pub state: FlowState,
}
