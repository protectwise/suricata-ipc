mod date_format;
mod json;
pub mod reader;

use crate::errors::Error;
use crate::intel::IdsRule;

use chrono::{DateTime, Utc};
use pw_thrift::association_id::AssociationId;
use pw_thrift::netflow::NetFlowId;
use pw_thrift::observation::{IdsEvent, Observation, ObservationData, ObservationInfo, Source};
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

impl Message {
    pub fn as_observation(
        &self,
        flow_id: &NetFlowId,
        intel: &IdsRule,
        ts: &DateTime<Utc>,
    ) -> Observation {
        let mut ids_data = IdsEvent::default();
        ids_data.timestamp_seconds = Some(self.timestamp.timestamp() as _);
        ids_data.timestamp_micros = Some(self.timestamp.timestamp_subsec_micros() as _);
        ids_data.signature_id = Some(self.alert.signature_id as _);
        ids_data.generator_id = Some(self.alert.gid as _);
        ids_data.revision = Some(self.alert.rev as _);
        ids_data.classification = intel.intel.classtype.clone();
        ids_data.priority_id = Some(self.alert.severity as _);
        ids_data.description = Some(intel.intel.msg.clone());

        let mut obs = Observation::default();
        obs.associated_id = Some(AssociationId::FlowId(flow_id.clone()));
        obs.flow_id = Some(flow_id.clone());
        obs.occurred_at = Some(self.timestamp.timestamp_millis() as _);
        obs.observed_at = Some(ts.timestamp_millis() as _);
        obs.data = Some(ObservationData::IdsEvent(ids_data));
        obs.source = Some(Source::Surricata);
        obs.kill_chain_stage = Some(intel.metadata.threat_mapping.kill_chain_stage);
        obs.confidence = Some(intel.metadata.threat_mapping.confidence);
        obs.severity = Some(intel.metadata.threat_mapping.severity);
        obs.category = Some(intel.metadata.threat_mapping.category);

        let mut info = ObservationInfo::default();
        info.list_id = Some(intel.id.list_id.clone());
        info.intel_key = Some(intel.id.key.clone());

        obs.observation_info = Some(info);

        Scorer::score(obs)
    }
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
    use crate::intel::parser::*;
    use chrono::offset::TimeZone;
    use chrono::Timelike;
    use pw_thrift::common::NTuple7;
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

    #[test]
    fn converts_to_observation() {
        let msg = r#"{"timestamp":"2017-12-18T10:48:14.627130-0700","flow_id":2061665895874790,"pcap_cnt":7,"event_type":"alert","src_ip":"10.151.223.136","src_port":26475,"dest_ip":"203.0.113.99","dest_port":80,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":4113433437,"signature_id":600074,"rev":1,"signature":"ProtectWise Canary Test 1.3 - Not Malicious","category":"","severity":3},"app_proto":"http","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":582,"bytes_toclient":302,"start":"2017-12-18T10:48:14.622822-0700"}}"#;

        let eve = Message::try_from(msg.as_bytes().as_ref()).expect("Failed to read eve message");

        let rule = IdsRule {
            id: RuleId {
                list_id: "list_id".to_owned(),
                key: "key".to_owned(),
            },
            metadata: RuleMetadata {
                status: RuleStatus::Enabled,
                tags: vec![],
                threat_mapping: ThreatInfo {
                    kill_chain_stage: pw_thrift::common::KillChainStage::Methodology,
                    category: pw_thrift::common::ThreatCategory::Malware,
                    confidence: 75i16,
                    severity: 60i32,
                },
                rule_behavior: RuleBehavior::Blacklist,
            },
            intel: IdsIntel {
                rule: "rule".to_owned(),
                gid: 100,
                sid: 1000,
                msg: "message".to_owned(),
                classtype: Some("classtype".to_owned()),
                references: vec![],
            },
        };

        let mut tuple7 = NTuple7::default();
        tuple7.src_ip = Some(pw_thrift::util::convert_ip_addr(&eve.src_ip));
        tuple7.src_port = Some(eve.src_port as _);
        tuple7.dst_ip = Some(pw_thrift::util::convert_ip_addr(&eve.dest_ip));
        tuple7.dst_port = Some(eve.dest_port as _);
        tuple7.proto = Some(eve.proto.clone());

        let mut flow_id = NetFlowId::default();
        flow_id.tuple7 = Some(tuple7);

        let now = Utc::now();
        let obs: pw_thrift::observation::Observation = eve.as_observation(&flow_id, &rule, &now);

        if let ObservationData::IdsEvent(ids) = obs.data.expect("No observation data") {
            let expected_timestamp = Utc
                .ymd(2017, 12, 18)
                .and_hms(17, 48, 14)
                .with_nanosecond(627130000)
                .expect("Invalid time");

            assert_eq!(
                ids.timestamp_seconds,
                Some(expected_timestamp.timestamp() as i32)
            );
            assert_eq!(ids.signature_id, Some(600074));
        } else {
            panic!("Observation data was not ids");
        }
    }
}
