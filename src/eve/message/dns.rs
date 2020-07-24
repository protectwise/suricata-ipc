use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Dns {
    #[serde(flatten)]
    pub event_fields: super::EventFields,
    pub info: DnsInfo,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DnsInfo {
    pub id: i32,
    #[serde(flatten)]
    pub event: DnsEventType,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DnsEventType {
    #[serde(rename = "query")]
    Query(DnsQuery),
    #[serde(rename = "answer")]
    Answer(DnsAnswer),
}

/// [2020-07-30T19:34:01Z INFO  suricata_ipc::eve::reader] {"timestamp":"2015-10-20T16:08:08.083366-0600","flow_id":2002523053901222,"event_type":"dns","src_ip":"192.168.89.2","src_port":36414,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","community_id":"1:6KH31DrKtXiYBf9dKMXt6n2rESo=","dns":{"type":"query","id":25510,"rrname":"localhost","rrtype":"A","tx_id":0}}
#[derive(Debug, Deserialize, Serialize)]
pub struct DnsQuery {
    pub tx_id: i32, //query
    #[serde(default)]
    pub rrname: String,
    #[serde(default)]
    pub rrtype: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DnsAnswer {
    pub flags: String,
    #[serde(default)]
    pub qr: bool,
    #[serde(default)]
    pub aa: bool,
    #[serde(default)]
    pub tc: bool,
    #[serde(default)]
    pub rd: bool,
    #[serde(default)]
    pub ra: bool,
    #[serde(default)]
    pub rrname: String,
    #[serde(default)]
    pub rrtype: String,
    #[serde(default)]
    pub rcode: String,
    #[serde(default)]
    pub answers: Vec<Answer>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Answer {
    #[serde(default)]
    pub rrname: String,
    #[serde(default)]
    pub rrtype: String,
    #[serde(default)]
    pub ttl: u64,
    #[serde(default)]
    pub rdata: String,
}
