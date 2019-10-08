use criterion::{criterion_group, criterion_main, Criterion};
use futures::StreamExt;
use log::*;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use suricata_rs::config::Config as SuricataConfig;
use suricata_rs::errors::Error;
use suricata_rs::intel::parser::{Rule, SensorRules};
use suricata_rs::intel::IntelCache;
use suricata_rs::*;

const SURICATA_YAML: &'static str = "suricata.yaml";
const CUSTOM_RULES: &'static str = "custom.rules";
const ALERT_SOCKET: &'static str = "suricata.alerts";

struct WrapperPacket<'a> {
    inner: &'a net_parser_rs::PcapRecord<'a>,
}

impl<'a> WrapperPacket<'a> {
    pub fn new(inner: &'a net_parser_rs::PcapRecord<'a>) -> WrapperPacket<'a> {
        WrapperPacket { inner }
    }
}

impl<'a> suricata_rs::ipc::AsIpcPacket for WrapperPacket<'a> {
    fn timestamp(&self) -> &std::time::SystemTime {
        &self.inner.timestamp
    }
    fn data(&self) -> &[u8] {
        &self.inner.payload
    }
}

async fn run_ids<T: AsRef<Path>>(
    pcap_path: T,
    nb_packets: usize,
) -> Result<(usize, Vec<Vec<u8>>), Error> {
    let cargo_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resources_path = cargo_dir.join("resources");

    let temp_file = tempfile::tempdir()
        .expect("Failed to create temp file")
        .into_path();

    let mut file = File::open(resources_path.join("s3.js")).expect("Failed to open rules file");
    let mut rule_bytes = vec![];
    file.read_to_end(&mut rule_bytes)
        .expect("Failed to read rules file");

    let rules: Vec<Rule> = Rule::try_from_slice(&rule_bytes).expect("Failed to parse rules");
    let sensor_rules = SensorRules {
        rules: rules,
        etag: vec![],
    };
    let cache: IntelCache = sensor_rules.into();
    let rules = temp_file.join(CUSTOM_RULES);
    cache
        .materialize_rules(rules.clone())
        .expect("Failed to materialize rules");

    let alert_path = temp_file.join(ALERT_SOCKET);
    let suricata_yaml = temp_file.join(SURICATA_YAML);

    let mut ids_args = SuricataConfig::default();
    ids_args.materialize_config_to = suricata_yaml;
    ids_args.alert_path = alert_path;
    ids_args.rule_path = rules;
    let mut ids = Ids::new(ids_args).await.expect("failed to create ids");

    let ids_output = ids.take_output().expect("No output");

    tokio::spawn(ids_output);

    let ids_alerts = ids.take_alerts().expect("No alerts");
    let mut ipc_server = ids.take_ipc_server().expect("No ids ipc server");

    let mut f = File::open(pcap_path).expect("Could not open pcap");
    let mut packet_bytes = vec![];
    f.read_to_end(&mut packet_bytes)
        .expect("Could not read packet_bytes");
    let (_, file) =
        net_parser_rs::CaptureFile::parse(&packet_bytes).expect("Failed to read packets");

    let mut packets_sent = 0;

    info!("Sending packets to ids");

    let records = file.records.into_inner();
    let mut packets_iter = records.chunks(100).map(|r| {
        r.iter()
            .map(|record| WrapperPacket::new(&record))
            .collect::<Vec<_>>()
    });
    let mut packets_to_send = vec![];

    while let Some(mut packets) = packets_iter.next() {
        for p in packets.drain(..) {
            let ipc_packet = suricata_rs::ipc::try_from(&p).expect("Failed to convert");
            packets_to_send.push(ipc_packet);
            if packets_to_send.len() == 1000 {
                let packets = std::mem::replace(&mut packets_to_send, vec![]);
                packets_sent += packets.len();
                ipc_server.send(packets).expect("Failed to send");
                std::thread::sleep(std::time::Duration::from_millis(10));
                info!("Sent {} packets", packets_sent);
            }

            if packets_sent >= nb_packets {
                break;
            }
        }
    }

    if !packets_to_send.is_empty() {
        let packets = std::mem::replace(&mut packets_to_send, vec![]);
        packets_sent += packets.len();
        ipc_server.send(packets).expect("Failed to send");
    }

    info!("Packets sent, closing connection");

    let mut ipc_pin = Pin::new(&mut ipc_server);
    ipc_pin.close().expect("Failed to close");

    let alerts: Vec<Result<Vec<_>, Error>> = ids_alerts.collect().await;
    let alerts: Result<Vec<_>, Error> = alerts.into_iter().collect();
    let alerts: Vec<_> = alerts?.into_iter().flatten().collect();

    info!("Finished collecting alerts");

    Ok((packets_sent, alerts))
}

fn bench_ids_process_4sics(c: &mut Criterion) {
    let benchmark = criterion::Benchmark::new("ids", |b| {
        let _ = env_logger::try_init();

        let rt = tokio::runtime::Runtime::new().expect("Could not create runtime");

        let pcap_path = pcaps::get_pcap_path("4SICS-GeekLounge-151020.pcap");

        b.iter(|| {
            let f = run_ids(pcap_path.clone(), 50000);

            let (packets_sent, alerts) = rt.block_on(f).expect("Failed to run");

            assert!(packets_sent >= 50000);
            assert_eq!(alerts.len(), 0);
        })
    });

    c.bench(
        "ids",
        benchmark
            .sample_size(10)
            .nresamples(1)
            .measurement_time(std::time::Duration::from_secs(15)),
    );
}

criterion_group!(benches, bench_ids_process_4sics);

//
// Benchmark: RUST_LOG=suricata_rs=info cargo bench --bench benches -- --verbose
// ids                     time:   [5.8620 s 5.8607 s 5.8620 s]
// slope  [5.8620 s 5.8620 s] R^2            [0.9999917 0.9999917]
// mean   [5.8617 s 5.8617 s] std. dev.      [6.1476 ms 6.1476 ms]
// median [5.8577 s 5.8577 s] med. abs. dev. [319.95 us 319.95 us]
criterion_main!(benches);
