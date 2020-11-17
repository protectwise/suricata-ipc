mod alert;
mod date_format;
mod dns;
mod file;
mod flow;
mod http;
mod smtp;
mod stats;
mod tcp;
mod tls;

pub use alert::{Alert, AlertFlowInfo, AlertInfo};
pub use date_format::parse_date_time;
pub use dns::{Dns, DnsAnswer, DnsEventType, DnsInfo, DnsQuery};
pub use file::{File, FileInfo, FileState};
pub use flow::{Flow, FlowInfo};
pub use http::Http;
pub use smtp::Smtp;
pub use stats::Stats;
pub use tcp::Tcp;
pub use tls::{Ja3, Tls};

use crate::Error;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum EventType {
    #[serde(rename = "alert")]
    Alert(Alert),
    #[serde(rename = "dns")]
    Dns(Dns),
    #[serde(rename = "flow")]
    Flow(Flow),
    #[serde(rename = "fileinfo")]
    File(File),
    #[serde(rename = "http")]
    Http(Http),
    #[serde(rename = "smtp")]
    Smtp(Smtp),
    #[serde(rename = "stats")]
    Stats(Stats),
    #[serde(rename = "tls")]
    Tls(Tls),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    #[serde(with = "date_format")]
    pub timestamp: DateTime<Utc>,
    #[serde(flatten)]
    pub event: EventType,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum State {
    #[serde(rename = "new")]
    New,
    #[serde(rename = "established")]
    Established,
    #[serde(rename = "closed")]
    Closed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventFields {
    pub src_ip: std::net::IpAddr,
    #[serde(default)]
    pub src_port: Option<u16>,
    pub dest_ip: std::net::IpAddr,
    #[serde(default)]
    pub dest_port: Option<u16>,
    pub proto: String,
    pub app_proto: Option<String>,
    pub community_id: Option<String>,
    pub tcp: Option<Tcp>,
}

impl std::convert::TryFrom<&[u8]> for Message {
    type Error = Error;
    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        log::trace!("Deserializing {}", String::from_utf8_lossy(v));
        serde_json::from_slice(v).map_err(|e| {
            let s = String::from_utf8_lossy(v);
            log::debug!("Failed to deserialize: {}", s);
            Error::from(e)
        })
    }
}

impl crate::intel::Observable for Message {
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp.clone()
    }

    fn key(&self) -> Option<crate::intel::IdsKey> {
        if let EventType::Alert(a) = &self.event {
            Some(crate::intel::IdsKey {
                gid: a.info.gid,
                sid: a.info.signature_id,
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::offset::TimeZone;
    use chrono::Timelike;
    use std::convert::TryFrom;

    #[test]
    fn should_deserialize_eve_alert() {
        let msg = r#"{"timestamp":"2017-12-18T10:48:14.627130-0700","flow_id":2061665895874790,"pcap_cnt":7,"event_type":"alert","src_ip":"10.151.223.136","src_port":26475,"dest_ip":"203.0.113.99","dest_port":80,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":4113433437,"signature_id":600074,"rev":1,"signature":"ProtectWise Canary Test 1.3 - Not Malicious","category":"","severity":3},"app_proto":"http","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":582,"bytes_toclient":302,"start":"2017-12-18T10:48:14.622822-0700"}}"#;

        let eve = Message::try_from(msg.as_bytes().as_ref()).expect("Failed to read eve message");

        let expected_timestamp = Utc
            .ymd(2017, 12, 18)
            .and_hms(17, 48, 14)
            .with_nanosecond(627130000)
            .expect("Invalid time");

        assert_eq!(eve.timestamp, expected_timestamp);

        if let EventType::Alert(eve) = eve.event {
            let expected_src_ip = "10.151.223.136"
                .parse::<std::net::IpAddr>()
                .expect("Failed to parse");

            assert_eq!(eve.event_fields.src_ip, expected_src_ip);
            assert_eq!(eve.info.signature_id, 600074);
        } else {
            panic!("Not an alert");
        }
    }

    #[test]
    fn should_deserialize_eve_alert_with_community_id() {
        let msg = r#"{"timestamp":"2017-12-18T10:48:14.627130-0700","flow_id":2061665895874790,"pcap_cnt":7,"event_type":"alert","src_ip":"10.151.223.136","src_port":26475,"dest_ip":"203.0.113.99","dest_port":80,"proto":"TCP","community_id":"1:3ZcLCpqiJpUyBlL6cvSAzm4Cn94=","tx_id":0,"alert":{"action":"allowed","gid":4113433437,"signature_id":600074,"rev":1,"signature":"ProtectWise Canary Test 1.3 - Not Malicious","category":"","severity":3},"app_proto":"http","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":582,"bytes_toclient":302,"start":"2017-12-18T10:48:14.622822-0700"}}"#;

        let eve = Message::try_from(msg.as_bytes().as_ref()).expect("Failed to read eve message");

        let expected_timestamp = Utc
            .ymd(2017, 12, 18)
            .and_hms(17, 48, 14)
            .with_nanosecond(627130000)
            .expect("Invalid time");

        assert_eq!(eve.timestamp, expected_timestamp);

        if let EventType::Alert(eve) = eve.event {
            let expected_src_ip = "10.151.223.136"
                .parse::<std::net::IpAddr>()
                .expect("Failed to parse");

            assert_eq!(eve.event_fields.src_ip, expected_src_ip);
            assert_eq!(eve.info.signature_id, 600074);
            assert_eq!(
                eve.event_fields.community_id,
                Some("1:3ZcLCpqiJpUyBlL6cvSAzm4Cn94=".to_owned())
            );
        } else {
            panic!("Not an alert");
        }
    }

    #[test]
    fn should_deserialize_eve_stats() {
        let msg = r#"{"timestamp":"2020-04-03T09:37:20.358120-0600","event_type":"stats","stats":{"uptime":8,"decoder":{"pkts":50900,"bytes":3999331,"invalid":0,"ipv4":49685,"ipv6":0,"ethernet":50900,"raw":0,"null":0,"sll":0,"tcp":44592,"udp":4629,"sctp":0,"icmpv4":464,"icmpv6":0,"ppp":0,"pppoe":0,"gre":0,"vlan":0,"vlan_qinq":0,"vxlan":0,"ieee8021ah":0,"teredo":0,"ipv4_in_ipv6":0,"ipv6_in_ipv6":0,"mpls":0,"avg_pkt_size":78,"max_pkt_size":153,"erspan":0,"dce":{"pkt_too_small":0}},"flow":{"memcap":0,"tcp":3152,"udp":425,"icmpv4":0,"icmpv6":0,"spare":0,"emerg_mode_entered":0,"emerg_mode_over":0,"tcp_reuse":0,"memuse":9076480},"defrag":{"ipv4":{"fragments":0,"reassembled":0,"timeouts":0},"ipv6":{"fragments":0,"reassembled":0,"timeouts":0},"max_frag_hits":0},"true":{"ipv4":{"pkt_too_small":0,"hlen_too_small":0,"iplen_smaller_than_hlen":0,"trunc_pkt":0,"opt_invalid":0,"opt_invalid_len":0,"opt_malformed":0,"opt_pad_required":0,"opt_eol_required":0,"opt_duplicate":0,"opt_unknown":0,"wrong_ip_version":0,"icmpv6":0,"frag_pkt_too_large":0,"frag_overlap":0,"frag_ignored":0},"icmpv4":{"pkt_too_small":0,"unknown_type":0,"unknown_code":0,"ipv4_trunc_pkt":0,"ipv4_unknown_ver":0},"icmpv6":{"unknown_type":0,"unknown_code":0,"pkt_too_small":0,"ipv6_unknown_version":0,"ipv6_trunc_pkt":0,"mld_message_with_invalid_hl":0,"unassigned_type":0,"experimentation_type":0},"ipv6":{"pkt_too_small":0,"trunc_pkt":0,"trunc_exthdr":0,"exthdr_dupl_fh":0,"exthdr_useless_fh":0,"exthdr_dupl_rh":0,"exthdr_dupl_hh":0,"exthdr_dupl_dh":0,"exthdr_dupl_ah":0,"exthdr_dupl_eh":0,"exthdr_invalid_optlen":0,"wrong_ip_version":0,"exthdr_ah_res_not_null":0,"hopopts_unknown_opt":0,"hopopts_only_padding":0,"dstopts_unknown_opt":0,"dstopts_only_padding":0,"rh_type_0":0,"zero_len_padn":0,"fh_non_zero_reserved_field":0,"data_after_none_header":0,"unknown_next_header":0,"icmpv4":0,"frag_pkt_too_large":0,"frag_overlap":0,"frag_ignored":0,"ipv4_in_ipv6_too_small":0,"ipv4_in_ipv6_wrong_version":0,"ipv6_in_ipv6_too_small":0,"ipv6_in_ipv6_wrong_version":0},"tcp":{"pkt_too_small":0,"hlen_too_small":0,"invalid_optlen":0,"opt_invalid_len":0,"opt_duplicate":0},"udp":{"pkt_too_small":0,"hlen_too_small":0,"hlen_invalid":0},"sll":{"pkt_too_small":0},"ethernet":{"pkt_too_small":0},"ppp":{"pkt_too_small":0,"vju_pkt_too_small":0,"ip4_pkt_too_small":0,"ip6_pkt_too_small":0,"wrong_type":0,"unsup_proto":0},"pppoe":{"pkt_too_small":0,"wrong_code":0,"malformed_tags":0},"gre":{"pkt_too_small":0,"wrong_version":0,"version0_recur":0,"version0_flags":0,"version0_hdr_too_big":0,"version0_malformed_sre_hdr":0,"version1_chksum":0,"version1_route":0,"version1_ssr":0,"version1_recur":0,"version1_flags":0,"version1_no_key":0,"version1_wrong_protocol":0,"version1_malformed_sre_hdr":0,"version1_hdr_too_big":0},"vlan":{"header_too_small":0,"unknown_type":0,"too_many_layers":0},"ieee8021ah":{"header_too_small":0},"ipraw":{"invalid_ip_version":0},"ltnull":{"pkt_too_small":0,"unsupported_type":0},"sctp":{"pkt_too_small":0},"mpls":{"header_too_small":0,"pkt_too_small":0,"bad_label_router_alert":0,"bad_label_implicit_null":0,"bad_label_reserved":0,"unknown_payload_type":0},"erspan":{"header_too_small":0,"unsupported_version":0,"too_many_vlan_layers":0}},"flow_bypassed":{"local_pkts":0,"local_bytes":0,"local_capture_pkts":0,"local_capture_bytes":0,"closed":0,"pkts":0,"bytes":0},"tcp":{"sessions":3150,"ssn_memcap_drop":0,"pseudo":0,"pseudo_failed":0,"invalid_checksum":0,"no_flow":0,"syn":3067,"synack":3067,"rst":4040,"midstream_pickups":83,"pkt_on_wrong_thread":0,"segment_memcap_drop":0,"stream_depth_reached":0,"reassembly_gap":2,"overlap":6283,"overlap_diff_data":0,"insert_data_normal_fail":0,"insert_data_overlap_fail":0,"insert_list_fail":0,"memuse":6451200,"reassembly_memuse":1458220},"detect":{"engines":[{"id":0,"last_reload":"2020-04-03T09:37:12.330695-0600","rules_loaded":21,"rules_failed":0}],"alert":0},"app_layer":{"flow":{"http":0,"ftp":0,"smtp":0,"tls":0,"ssh":0,"imap":0,"smb":0,"dcerpc_tcp":0,"dns_tcp":0,"nfs_tcp":0,"ntp":1,"ftp-data":0,"tftp":0,"ikev2":0,"krb5_tcp":0,"dhcp":0,"snmp":0,"rfb":0,"failed_tcp":2,"dcerpc_udp":0,"dns_udp":423,"nfs_udp":0,"krb5_udp":0,"failed_udp":1},"tx":{"http":0,"ftp":0,"smtp":0,"tls":0,"ssh":0,"imap":0,"smb":0,"dcerpc_tcp":0,"dns_tcp":0,"nfs_tcp":0,"ntp":1,"ftp-data":0,"tftp":0,"ikev2":0,"krb5_tcp":0,"dhcp":0,"snmp":0,"rfb":0,"dcerpc_udp":0,"dns_udp":4620,"nfs_udp":0,"krb5_udp":0},"expectations":0},"flow_mgr":{"closed_pruned":0,"new_pruned":0,"est_pruned":0,"bypassed_pruned":0,"flows_checked":0,"flows_notimeout":0,"flows_timeout":0,"flows_timeout_inuse":0,"flows_removed":0,"rows_checked":0,"rows_skipped":0,"rows_empty":0,"rows_busy":0,"rows_maxlen":0},"http":{"memuse":0,"memcap":0},"ftp":{"memuse":0,"memcap":0}}}"#;

        let eve = Message::try_from(msg.as_bytes().as_ref()).expect("Failed to read eve message");

        let expected_timestamp = Utc
            .ymd(2020, 4, 3)
            .and_hms(15, 37, 20)
            .with_nanosecond(358120000)
            .expect("Invalid time");

        assert_eq!(eve.timestamp, expected_timestamp);

        if let EventType::Stats(stats) = eve.event {
            assert_eq!(stats.info.decoder.pkts, 50_900)
        } else {
            panic!("Not stats")
        }
    }

    #[test]
    fn should_deserialize_eve_flow() {
        let msg = r#"{"timestamp":"1969-12-31T17:00:00.000000-0700","flow_id":1042873772049837,"event_type":"flow","src_ip":"10.10.10.30","src_port":57656,"dest_ip":"10.10.10.10","dest_port":102,"proto":"TCP","flow":{"pkts_toserver":3,"pkts_toclient":8,"bytes_toserver":186,"bytes_toclient":480,"start":"2015-10-20T11:24:10.230829-0600","end":"2015-10-20T11:24:46.195059-0600","age":36,"state":"closed","reason":"shutdown","alerted":false},"tcp":{"tcp_flags":"16","tcp_flags_ts":"16","tcp_flags_tc":"16","syn":true,"rst":true,"ack":true,"state":"closed"}}"#;

        let eve = Message::try_from(msg.as_bytes().as_ref()).expect("Failed to read eve message");

        if let EventType::Flow(flow) = eve.event {
            assert_eq!(
                flow.event_fields.src_ip,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 10, 10, 30))
            );
            assert_eq!(flow.event_fields.src_port.unwrap(), 57_656);
            assert_eq!(flow.event_fields.proto.as_str(), "TCP");
            assert!(flow.event_fields.app_proto.is_none());
            let expected_timestamp = Utc
                .ymd(2015, 10, 20)
                .and_hms(17, 24, 10)
                .with_nanosecond(230829000)
                .expect("Invalid time");

            assert_eq!(flow.info.start, expected_timestamp);

            assert_eq!(flow.info.pkts_toserver, 3);
        } else {
            panic!("Not flow");
        }
    }

    #[test]
    fn should_deserialize_eve_icmp_flow() {
        let msg = r#"{"timestamp":"2016-06-16T15:07:24.422364-0600","flow_id":1980961674612149,"event_type":"flow","src_ip":"fe80:0000:0000:0000:7836:ddff:fe67:941f","dest_ip":"ff02:0000:0000:0000:0000:0000:0000:0002","proto":"IPV6-ICMP","icmp_type":133,"icmp_code":0,"flow":{"pkts_toserver":3,"pkts_toclient":0,"bytes_toserver":210,"bytes_toclient":0,"start":"2016-06-16T15:06:53.839093-0600","end":"2016-06-16T15:07:01.859044-0600","age":8,"state":"new","reason":"shutdown","alerted":false},"community_id":"1:ZJ+Tb/l5rNs6uZNnjO05XBTBCYE="}"#;

        let eve = Message::try_from(msg.as_bytes().as_ref()).expect("Failed to read eve message");

        if let EventType::Flow(flow) = eve.event {
            assert_eq!(
                flow.event_fields.src_ip,
                std::net::IpAddr::V6("fe80:0000:0000:0000:7836:ddff:fe67:941f".parse().unwrap())
            );
            assert!(flow.event_fields.src_port.is_none());
            assert_eq!(flow.event_fields.proto.as_str(), "IPV6-ICMP");
            assert!(flow.event_fields.app_proto.is_none());
            let expected_timestamp = Utc
                .ymd(2016, 6, 16)
                .and_hms(21, 6, 53)
                .with_nanosecond(839093000)
                .expect("Invalid time");

            assert_eq!(flow.info.start, expected_timestamp);

            assert_eq!(flow.info.pkts_toserver, 3);
        } else {
            panic!("Not flow");
        }
    }

    #[test]
    fn should_deserialize_eve_flow_with_community_id() {
        let msg = r#"{"timestamp":"1969-12-31T17:00:00.000000-0700","flow_id":1042873772049837,"event_type":"flow","src_ip":"10.10.10.30","src_port":57656,"dest_ip":"10.10.10.10","dest_port":102,"proto":"TCP","flow":{"pkts_toserver":3,"pkts_toclient":8,"bytes_toserver":186,"bytes_toclient":480,"start":"2015-10-20T11:24:10.230829-0600","end":"2015-10-20T11:24:46.195059-0600","age":36,"state":"closed","reason":"shutdown","alerted":false},"tcp":{"tcp_flags":"16","tcp_flags_ts":"16","tcp_flags_tc":"16","syn":true,"rst":true,"ack":true,"state":"closed"},"community_id":"1:3ZcLCpqiJpUyBlL6cvSAzm4Cn94="}"#;

        let eve = Message::try_from(msg.as_bytes().as_ref()).expect("Failed to read eve message");

        if let EventType::Flow(flow) = eve.event {
            assert_eq!(
                flow.event_fields.src_ip,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 10, 10, 30))
            );
            assert_eq!(flow.event_fields.src_port.unwrap(), 57_656);
            assert_eq!(flow.event_fields.proto.as_str(), "TCP");
            assert!(flow.event_fields.app_proto.is_none());
            let expected_timestamp = Utc
                .ymd(2015, 10, 20)
                .and_hms(17, 24, 10)
                .with_nanosecond(230829000)
                .expect("Invalid time");

            assert_eq!(flow.info.start, expected_timestamp);

            assert_eq!(flow.info.pkts_toserver, 3);
            assert_eq!(
                flow.event_fields.community_id,
                Some("1:3ZcLCpqiJpUyBlL6cvSAzm4Cn94=".to_owned())
            );
        } else {
            panic!("Not stats");
        }
    }

    #[test]
    fn should_deserialize_eve_open_flow() {
        let msg = r#"{"timestamp":"1969-12-31T17:00:00.000000-0700","flow_id":1005493326901652,"event_type":"flow","src_ip":"192.168.89.2","src_port":27554,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","app_proto":"dns","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":69,"bytes_toclient":97,"start":"2015-10-20T14:48:18.979348-0600","end":"2015-10-20T14:48:18.979458-0600","age":0,"state":"new","reason":"shutdown","alerted":false}}"#;

        let eve = Message::try_from(msg.as_bytes().as_ref()).expect("Failed to read eve message");

        if let EventType::Flow(flow) = eve.event {
            assert_eq!(
                flow.event_fields.dest_ip,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8))
            );
            assert_eq!(flow.event_fields.dest_port.unwrap(), 53);
            assert_eq!(flow.event_fields.proto.as_str(), "UDP");
            assert_eq!(flow.event_fields.app_proto, Some("dns".to_owned()));

            let expected_timestamp = Utc
                .ymd(2015, 10, 20)
                .and_hms(20, 48, 18)
                .with_nanosecond(979458000)
                .expect("Invalid time");

            assert_eq!(flow.info.end, expected_timestamp);

            assert_eq!(flow.info.bytes_toserver, 69)
        } else {
            panic!("Not flow")
        }
    }

    #[test]
    fn should_decode_eve_dns() {
        let msg = r#"{"timestamp":"2015-10-20T16:07:21.584630-0600","flow_id":482657058359332,"event_type":"dns","src_ip":"192.168.88.61","src_port":949,"dest_ip":"192.168.88.1","dest_port":53,"proto":"UDP","community_id":"1:P7jixReUPBkrfEsrEJysVvyhqKc=","dns":{"version":2,"type":"answer","id":56281,"flags":"8185","qr":true,"rd":true,"ra":true,"rrname":"time.nist.gov","rrtype":"A","rcode":"REFUSED"}}"#;

        let eve = Message::try_from(msg.as_bytes().as_ref()).expect("Failed to read eve message");

        if let EventType::Dns(_d) = eve.event {
        } else {
            panic!("Not dns")
        }
    }

    #[test]
    fn should_decode_complete_stats() {
        let msg = r#"{"timestamp":"2020-07-30T11:02:35.845000-0600","event_type":"stats","stats":{"uptime":15,"decoder":{"pkts":0,"bytes":0,"invalid":0,"ipv4":0,"ipv6":0,"ethernet":0,"chdlc":0,"raw":0,"null":0,"sll":0,"tcp":0,"udp":0,"sctp":0,"icmpv4":0,"icmpv6":0,"ppp":0,"pppoe":0,"gre":0,"vlan":0,"vlan_qinq":0,"vxlan":0,"ieee8021ah":0,"teredo":0,"ipv4_in_ipv6":0,"ipv6_in_ipv6":0,"mpls":0,"avg_pkt_size":0,"max_pkt_size":0,"erspan":0,"event":{"ipv4":{"pkt_too_small":0,"hlen_too_small":0,"iplen_smaller_than_hlen":0,"trunc_pkt":0,"opt_invalid":0,"opt_invalid_len":0,"opt_malformed":0,"opt_pad_required":0,"opt_eol_required":0,"opt_duplicate":0,"opt_unknown":0,"wrong_ip_version":0,"icmpv6":0,"frag_pkt_too_large":0,"frag_overlap":0,"frag_ignored":0},"icmpv4":{"pkt_too_small":0,"unknown_type":0,"unknown_code":0,"ipv4_trunc_pkt":0,"ipv4_unknown_ver":0},"icmpv6":{"unknown_type":0,"unknown_code":0,"pkt_too_small":0,"ipv6_unknown_version":0,"ipv6_trunc_pkt":0,"mld_message_with_invalid_hl":0,"unassigned_type":0,"experimentation_type":0},"ipv6":{"pkt_too_small":0,"trunc_pkt":0,"trunc_exthdr":0,"exthdr_dupl_fh":0,"exthdr_useless_fh":0,"exthdr_dupl_rh":0,"exthdr_dupl_hh":0,"exthdr_dupl_dh":0,"exthdr_dupl_ah":0,"exthdr_dupl_eh":0,"exthdr_invalid_optlen":0,"wrong_ip_version":0,"exthdr_ah_res_not_null":0,"hopopts_unknown_opt":0,"hopopts_only_padding":0,"dstopts_unknown_opt":0,"dstopts_only_padding":0,"rh_type_0":0,"zero_len_padn":0,"fh_non_zero_reserved_field":0,"data_after_none_header":0,"unknown_next_header":0,"icmpv4":0,"frag_pkt_too_large":0,"frag_overlap":0,"frag_ignored":0,"ipv4_in_ipv6_too_small":0,"ipv4_in_ipv6_wrong_version":0,"ipv6_in_ipv6_too_small":0,"ipv6_in_ipv6_wrong_version":0},"tcp":{"pkt_too_small":0,"hlen_too_small":0,"invalid_optlen":0,"opt_invalid_len":0,"opt_duplicate":0},"udp":{"pkt_too_small":0,"hlen_too_small":0,"hlen_invalid":0},"sll":{"pkt_too_small":0},"ethernet":{"pkt_too_small":0},"ppp":{"pkt_too_small":0,"vju_pkt_too_small":0,"ip4_pkt_too_small":0,"ip6_pkt_too_small":0,"wrong_type":0,"unsup_proto":0},"pppoe":{"pkt_too_small":0,"wrong_code":0,"malformed_tags":0},"gre":{"pkt_too_small":0,"wrong_version":0,"version0_recur":0,"version0_flags":0,"version0_hdr_too_big":0,"version0_malformed_sre_hdr":0,"version1_chksum":0,"version1_route":0,"version1_ssr":0,"version1_recur":0,"version1_flags":0,"version1_no_key":0,"version1_wrong_protocol":0,"version1_malformed_sre_hdr":0,"version1_hdr_too_big":0},"vlan":{"header_too_small":0,"unknown_type":0,"too_many_layers":0},"ieee8021ah":{"header_too_small":0},"ipraw":{"invalid_ip_version":0},"ltnull":{"pkt_too_small":0,"unsupported_type":0},"sctp":{"pkt_too_small":0},"mpls":{"header_too_small":0,"pkt_too_small":0,"bad_label_router_alert":0,"bad_label_implicit_null":0,"bad_label_reserved":0,"unknown_payload_type":0},"erspan":{"header_too_small":0,"unsupported_version":0,"too_many_vlan_layers":0},"dce":{"pkt_too_small":0}}},"flow":{"memcap":0,"tcp":0,"udp":0,"icmpv4":0,"icmpv6":0,"spare":10000,"emerg_mode_entered":0,"emerg_mode_over":0,"tcp_reuse":0,"memuse":11910016},"defrag":{"ipv4":{"fragments":0,"reassembled":0,"timeouts":0},"ipv6":{"fragments":0,"reassembled":0,"timeouts":0},"max_frag_hits":0},"flow_bypassed":{"local_pkts":0,"local_bytes":0,"local_capture_pkts":0,"local_capture_bytes":0,"closed":0,"pkts":0,"bytes":0},"tcp":{"sessions":0,"ssn_memcap_drop":0,"pseudo":0,"pseudo_failed":0,"invalid_checksum":0,"no_flow":0,"syn":0,"synack":0,"rst":0,"midstream_pickups":0,"pkt_on_wrong_thread":0,"segment_memcap_drop":0,"stream_depth_reached":0,"reassembly_gap":0,"overlap":0,"overlap_diff_data":0,"insert_data_normal_fail":0,"insert_data_overlap_fail":0,"insert_list_fail":0,"memuse":537600,"reassembly_memuse":98304},"detect":{"engines":[{"id":0,"last_reload":"2020-07-30T11:02:20.833611-0600","rules_loaded":21,"rules_failed":0}],"alert":0},"app_layer":{"flow":{"http":0,"ftp":0,"smtp":0,"tls":0,"ssh":0,"imap":0,"smb":0,"dcerpc_tcp":0,"dns_tcp":0,"nfs_tcp":0,"ntp":0,"ftp-data":0,"tftp":0,"ikev2":0,"krb5_tcp":0,"dhcp":0,"snmp":0,"sip":0,"rfb":0,"rdp":0,"failed_tcp":0,"dcerpc_udp":0,"dns_udp":0,"nfs_udp":0,"krb5_udp":0,"failed_udp":0},"tx":{"http":0,"ftp":0,"smtp":0,"tls":0,"ssh":0,"imap":0,"smb":0,"dcerpc_tcp":0,"dns_tcp":0,"nfs_tcp":0,"ntp":0,"ftp-data":0,"tftp":0,"ikev2":0,"krb5_tcp":0,"dhcp":0,"snmp":0,"sip":0,"rfb":0,"rdp":0,"dcerpc_udp":0,"dns_udp":0,"nfs_udp":0,"krb5_udp":0},"expectations":0},"flow_mgr":{"closed_pruned":0,"new_pruned":0,"est_pruned":0,"bypassed_pruned":0,"flows_checked":0,"flows_notimeout":0,"flows_timeout":0,"flows_timeout_inuse":0,"flows_removed":0,"rows_checked":32768,"rows_skipped":32768,"rows_empty":0,"rows_busy":0,"rows_maxlen":0},"http":{"memuse":0,"memcap":0},"ftp":{"memuse":0,"memcap":0}}}"#;

        let eve = Message::try_from(msg.as_bytes().as_ref()).expect("Failed to read eve message");

        if let EventType::Stats(_s) = eve.event {
        } else {
            panic!("Not stats")
        }
    }

    #[test]
    fn should_decode_dns_query() {
        let msg = r#"{"timestamp":"2015-10-20T16:08:08.083366-0600","flow_id":2002523053901222,"event_type":"dns","src_ip":"192.168.89.2","src_port":36414,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","community_id":"1:6KH31DrKtXiYBf9dKMXt6n2rESo=","dns":{"type":"query","id":25510,"rrname":"localhost","rrtype":"A","tx_id":0}}"#;

        let eve = Message::try_from(msg.as_bytes().as_ref()).expect("Failed to read eve message");

        if let EventType::Dns(d) = eve.event {
            if let DnsEventType::Query(_d) = d.info.event {
            } else {
                panic!("Not query");
            }
        } else {
            panic!("Not dns");
        }
    }

    #[test]
    fn should_decode_dns_answer() {
        let msg = r#"{"timestamp":"2015-10-20T16:10:02.112993-0600","flow_id":2176658129130895,"event_type":"dns","src_ip":"192.168.88.61","src_port":949,"dest_ip":"192.168.88.1","dest_port":53,"proto":"UDP","community_id":"1:P7jixReUPBkrfEsrEJysVvyhqKc=","dns":{"version":2,"type":"answer","id":56361,"flags":"8185","qr":true,"rd":true,"ra":true,"rrname":"time.nist.gov","rrtype":"A","rcode":"REFUSED"}}"#;

        let eve = Message::try_from(msg.as_bytes().as_ref()).expect("Failed to read eve message");

        if let EventType::Dns(d) = eve.event {
            if let DnsEventType::Answer(_d) = d.info.event {
            } else {
                panic!("Not answer");
            }
        } else {
            panic!("Not dns")
        }
    }

    #[test]
    fn should_decode_file() {
        let msg = r#"{"timestamp":"2016-06-16T15:07:06.802717-0600","flow_id":2180082800938789,"event_type":"fileinfo","src_ip":"10.3.1.1","src_port":445,"dest_ip":"10.3.1.2","dest_port":56746,"proto":"TCP","smb":{"id":27,"dialect":"2.02","command":"SMB2_COMMAND_READ","status":"STATUS_END_OF_FILE","status_code":"0xc0000011","session_id":706141969,"tree_id":201977730,"filename":"file69.txt","share":"\\\\10.3.1.1\\public","fuid":"96c8e081-0000-0000-441e-a47e00000000"},"app_proto":"smb","fileinfo":{"filename":"file69.txt","sid":[],"gaps":false,"state":"CLOSED","stored":false,"size":3109,"tx_id":26}}"#;

        let eve = Message::try_from(msg.as_bytes().as_ref()).expect("Failed to read eve message");

        if let EventType::File(v) = eve.event {
            assert!(!v.info.filename.is_empty());
            assert!(!v.info.stored);
        } else {
            panic!("Not http")
        }
    }

    #[test]
    fn should_decode_http() {
        let msg = r#"{"timestamp":"2020-08-05T13:32:29.341318+0000","flow_id":1925256485615034,"event_type":"http","src_ip":"16.0.0.1","src_port":41668,"dest_ip":"48.0.0.1","dest_port":80,"proto":"TCP","tx_id":0,"community_id":"1:p1ceBUuGcR8ILP4a2kUZp97NUQM=","http":{"hostname":"22.0.0.3","url":"/3384","http_user_agent":"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)","http_content_type":"text/html","request_headers":[{"name":"Host","value":"22.0.0.3"},{"name":"Connection","value":"Keep-Alive"},{"name":"User-Agent","value":"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)"},{"name":"Accept","value":"*/*"},{"name":"Accept-Language","value":"en-us"},{"name":"Accept-Encoding","value":"gzip, deflate, compress"}],"response_headers":[{"name":"Server","value":"Microsoft-IIS/6.0"},{"name":"Content-Type","value":"text/html"},{"name":"Content-Length","value":"32000"}]}}"#;

        let eve = Message::try_from(msg.as_bytes().as_ref()).expect("Failed to read eve message");

        if let EventType::Http(v) = eve.event {
            assert!(!v.info.request_headers.is_empty());
            assert!(!v.info.response_headers.is_empty());
        } else {
            panic!("Not http")
        }
    }
}
