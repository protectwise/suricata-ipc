//! # Pcap File Example
//! Example of reading packets from a file, passing them to suricata via bellini, and receiving
//! alerts
use bellini::prelude::*;
use futures::TryStreamExt;
use std::io::Read;

struct WrapperPacket<'a> {
    inner: &'a net_parser_rs::PcapRecord<'a>,
}

impl<'a> WrapperPacket<'a> {
    pub fn new(inner: &'a net_parser_rs::PcapRecord<'a>) -> WrapperPacket {
        WrapperPacket { inner }
    }
}

impl<'a> AsIpcPacket for WrapperPacket<'a> {
    fn timestamp(&self) -> &std::time::SystemTime {
        &self.inner.timestamp
    }
    fn data(&self) -> &[u8] {
        self.inner.payload
    }
}

async fn send_packets(ids: &mut Ids) -> Result<usize, Error> {
    let cargo_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let pcap_path = cargo_dir
        .parent().expect("No parent")
        .parent().expect("No parent")
        .join("resources")
        .join("testmyids.pcap");

    let mut f = std::fs::File::open(pcap_path).expect("Could not open file");
    let mut pcap_bytes = vec![];
    f.read_to_end(&mut pcap_bytes).expect("Failed to read file");
    let (_, f) = net_parser_rs::CaptureFile::parse(&pcap_bytes).expect("Failed to parse");

    let mut packets_sent = 0;

    println!("Sending packets to ids");

    let records = f.records.into_inner();
    let mut packets = records.chunks(100).map(|r| {
        r.iter()
            .map(|record| WrapperPacket::new(record))
            .collect::<Vec<_>>()
    });

    while let Some(ref packets) = packets.next() {
        packets_sent += ids.send(packets.as_slice()).expect("Failed to send packets");
        tokio::timer::delay_for(std::time::Duration::from_millis(10)).await;
        println!("Sent {} packets", packets_sent);
    }

    Ok(packets_sent)
}

#[tokio::main]
async fn main() {
    let resources = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().expect("Invalid path")
        .parent().expect("Invalid path")
        .join("resources");
    let config = Config::default();
    let rules = Rules::from_path(resources.join("test.rules")).expect("Could not parse rules");
    let cache: IntelCache<Rule> = rules.into();
    cache.materialize_rules(config.rule_path.clone()).expect("Failed to materialize rules");

    let mut ids = Ids::new(config).await.expect("Failed to create ids");
    let ids_alerts = ids.take_alerts().expect("No alerts");

    send_packets(&mut ids).await.expect("Failed to send packets");

    let alerts: Result<Vec<_>, Error> = ids_alerts.try_collect().await;
    let alerts: Result<Vec<_>, Error> = alerts.expect("Failed to receive alerts")
        .into_iter().flat_map(|v| v).collect();
    let alerts = alerts.expect("Failed to parse alerts");

    for eve in alerts {
        println!("Eve={:?}", eve);
        if let Some(intel) = cache.observed(eve) {
            if let Observed::Alert { rule, message: _ } = intel {
                println!("Rule={:?}", rule);
            }
        }
    }
}