use suricata_rs::prelude::*;
use log::*;
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

pub async fn send_packets(ids: Ids) {
    let mut ids = ids;

    tokio::timer::delay_for(std::time::Duration::from_secs(1)).await;

    let cargo_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let pcap_path = cargo_dir
        .parent()
        .expect("No parent")
        .parent()
        .expect("No parent")
        .join("resources")
        .join("testmyids.pcap");

    let mut f = std::fs::File::open(pcap_path).expect("Could not open file");
    let mut pcap_bytes = vec![];
    f.read_to_end(&mut pcap_bytes).expect("Failed to read file");
    let (_, f) = net_parser_rs::CaptureFile::parse(&pcap_bytes).expect("Failed to parse");

    let mut packets_sent = 0;

    info!("Sending packets to ids");

    let records = f.records.into_inner();
    let mut packets = records.chunks(100).map(|r| {
        r.iter()
            .map(|record| WrapperPacket::new(record))
            .collect::<Vec<_>>()
    });

    while let Some(ref packets) = packets.next() {
        packets_sent += ids
            .send(packets.as_slice())
            .expect("Failed to send packets");
        tokio::timer::delay_for(std::time::Duration::from_millis(10)).await;
        info!("Sent {} packets", packets_sent);
    }

    info!("Send complete. Sent {} packets to suricata", packets_sent);

    ids.close().expect("Failed to close");
}
