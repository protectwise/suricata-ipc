use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Decoder {
    pub pkts: usize,
    pub bytes: usize,
    pub invalid: usize,
    pub ipv4: usize,
    pub ipv6: usize,
    pub ethernet: usize,
    pub tcp: usize,
    pub udp: usize,
    pub sctp: usize,
    pub icmpv4: usize,
    pub icmpv6: usize,
    pub vxlan: usize,
    pub avg_pkt_size: usize,
    pub max_pkt_size: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Flow {
    pub tcp: usize,
    pub udp: usize,
    pub emerg_mode_entered: usize,
    pub emerg_mode_over: usize,
    pub memuse: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Tcp {
    pub sessions: usize,
    pub midstream_pickups: usize,
    pub stream_depth_reached: usize,
    pub memuse: usize,
    pub reassembly_memuse: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Stats {
    #[serde(rename = "stats")]
    pub info: StatsInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatsInfo {
    pub uptime: i64,
    pub decoder: Decoder,
    pub flow: Flow,
    pub tcp: Tcp,
}
