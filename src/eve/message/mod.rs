mod alert;
mod date_format;
mod flow;
mod stats;

pub use alert::Alert;
pub use flow::Flow;
pub use stats::Stats;

use crate::Error;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum EventType {
    #[serde(rename = "alert")]
    Alert(Alert),
    #[serde(rename = "stats")]
    Stats { stats: Stats },
    #[serde(rename = "flow")]
    Flow(Flow),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    #[serde(with = "date_format")]
    pub timestamp: DateTime<Utc>,
    #[serde(flatten)]
    pub event: EventType,
}

impl std::convert::TryFrom<&[u8]> for Message {
    type Error = Error;
    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        log::debug!("Deserializing {}", String::from_utf8_lossy(v));
        serde_json::from_slice(v).map_err(|e| {
            let s = String::from_utf8_lossy(v);
            log::debug!("Failed to deserialize: {}", s);
            Error::SerdeJson(e)
        })
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

            assert_eq!(eve.src_ip, expected_src_ip);
            assert_eq!(eve.alert.signature_id, 600074);
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

            assert_eq!(eve.src_ip, expected_src_ip);
            assert_eq!(eve.alert.signature_id, 600074);
            assert_eq!(eve.community_id, Some("1:3ZcLCpqiJpUyBlL6cvSAzm4Cn94=".to_owned()));
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

        if let EventType::Stats { stats } = eve.event {
            assert_eq!(stats.decoder.pkts, 50_900)
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
                flow.src_ip,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 10, 10, 30))
            );
            assert_eq!(flow.src_port, 57_656);
            assert_eq!(flow.proto.as_str(), "TCP");
            assert!(flow.app_proto.is_none());
            let expected_timestamp = Utc
                .ymd(2015, 10, 20)
                .and_hms(17, 24, 10)
                .with_nanosecond(230829000)
                .expect("Invalid time");

            assert_eq!(flow.state.start, expected_timestamp);

            assert_eq!(flow.state.pkts_toserver, 3);
        } else {
            panic!("Not stats");
        }
    }

    #[test]
    fn should_deserialize_eve_flow_with_community_id() {
        let msg = r#"{"timestamp":"1969-12-31T17:00:00.000000-0700","flow_id":1042873772049837,"event_type":"flow","src_ip":"10.10.10.30","src_port":57656,"dest_ip":"10.10.10.10","dest_port":102,"proto":"TCP","flow":{"pkts_toserver":3,"pkts_toclient":8,"bytes_toserver":186,"bytes_toclient":480,"start":"2015-10-20T11:24:10.230829-0600","end":"2015-10-20T11:24:46.195059-0600","age":36,"state":"closed","reason":"shutdown","alerted":false},"tcp":{"tcp_flags":"16","tcp_flags_ts":"16","tcp_flags_tc":"16","syn":true,"rst":true,"ack":true,"state":"closed"},"community_id":"1:3ZcLCpqiJpUyBlL6cvSAzm4Cn94="}"#;

        let eve = Message::try_from(msg.as_bytes().as_ref()).expect("Failed to read eve message");

        if let EventType::Flow(flow) = eve.event {
            assert_eq!(
                flow.src_ip,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 10, 10, 30))
            );
            assert_eq!(flow.src_port, 57_656);
            assert_eq!(flow.proto.as_str(), "TCP");
            assert!(flow.app_proto.is_none());
            let expected_timestamp = Utc
                .ymd(2015, 10, 20)
                .and_hms(17, 24, 10)
                .with_nanosecond(230829000)
                .expect("Invalid time");

            assert_eq!(flow.state.start, expected_timestamp);

            assert_eq!(flow.state.pkts_toserver, 3);
            assert_eq!(flow.community_id, Some("1:3ZcLCpqiJpUyBlL6cvSAzm4Cn94=".to_owned()));
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
                flow.dest_ip,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8))
            );
            assert_eq!(flow.dest_port, 53);
            assert_eq!(flow.proto.as_str(), "UDP");
            assert_eq!(flow.app_proto, Some("dns".to_owned()));

            let expected_timestamp = Utc
                .ymd(2015, 10, 20)
                .and_hms(20, 48, 18)
                .with_nanosecond(979458000)
                .expect("Invalid time");

            assert_eq!(flow.state.end, expected_timestamp);

            assert_eq!(flow.state.bytes_toserver, 69)
        } else {
            panic!("Not stats")
        }
    }

    #[tokio::test]
    #[ignore]
    async fn should_decode_eve_dns() {
        let _msg = r#"{"timestamp":"2015-10-20T16:07:21.584630-0600","flow_id":482657058359332,"event_type":"dns","src_ip":"192.168.88.61","src_port":949,"dest_ip":"192.168.88.1","dest_port":53,"proto":"UDP","community_id":"1:P7jixReUPBkrfEsrEJysVvyhqKc=","dns":{"version":2,"type":"answer","id":56281,"flags":"8185","qr":true,"rd":true,"ra":true,"rrname":"time.nist.gov","rrtype":"A","rcode":"REFUSED"}}"#;
    }
}
