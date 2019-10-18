mod date_format;
mod json;
mod reader;

pub use reader::EveReader as EveReader;
use crate::errors::Error;

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
pub struct Message {
    #[serde(with = "date_format")]
    pub timestamp: DateTime<Utc>,
    pub src_ip: std::net::IpAddr,
    pub src_port: u32,
    pub dest_ip: std::net::IpAddr,
    pub dest_port: u32,
    pub proto: String,
    pub alert: AlertInfo,
    pub flow: AlertFlowInfo,
}

impl std::convert::TryFrom<&[u8]> for Message {
    type Error = Error;
    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(v).map_err(Error::SerdeJson)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::offset::TimeZone;
    use chrono::Timelike;
    use std::convert::TryFrom;

    #[test]
    fn deserializes_eve() {
        let msg = r#"{"timestamp":"2017-12-18T10:48:14.627130-0700","flow_id":2061665895874790,"pcap_cnt":7,"event_type":"alert","src_ip":"10.151.223.136","src_port":26475,"dest_ip":"203.0.113.99","dest_port":80,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":4113433437,"signature_id":600074,"rev":1,"signature":"ProtectWise Canary Test 1.3 - Not Malicious","category":"","severity":3},"app_proto":"http","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":582,"bytes_toclient":302,"start":"2017-12-18T10:48:14.622822-0700"}}"#;

        let eve = Message::try_from(msg.as_bytes().as_ref()).expect("Failed to read eve message");

        let expected_src_ip = "10.151.223.136"
            .parse::<std::net::IpAddr>()
            .expect("Failed to parse");
        let expected_timestamp = Utc
            .ymd(2017, 12, 18)
            .and_hms(17, 48, 14)
            .with_nanosecond(627130000)
            .expect("Invalid time");

        assert_eq!(eve.src_ip, expected_src_ip);
        assert_eq!(eve.timestamp, expected_timestamp);
        assert_eq!(eve.alert.signature_id, 600074);
    }
}
