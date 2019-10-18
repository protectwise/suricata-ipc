use criterion::{criterion_group, criterion_main, Criterion};
use futures::TryStreamExt;
use log::*;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use bellini::prelude::*;

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

impl<'a> AsIpcPacket for WrapperPacket<'a> {
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
) -> Result<(usize, Vec<EveMessage>), Error> {
    let cargo_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resources_path = cargo_dir.join("resources");

    let temp_file = tempfile::tempdir()
        .expect("Failed to create temp file")
        .into_path();

    let rules = Rules::from_path(resources_path.join("test.rules")).expect("Failed to read rules");
    let cache: IntelCache<_> = rules.into();
    let rules = temp_file.join(CUSTOM_RULES);
    cache
        .materialize_rules(rules.clone())
        .expect("Failed to materialize rules");

    let alert_path = temp_file.join(ALERT_SOCKET);
    let suricata_yaml = temp_file.join(SURICATA_YAML);

    let mut ids_args = Config::default();
    ids_args.materialize_config_to = suricata_yaml;
    ids_args.alert_path = alert_path;
    ids_args.rule_path = rules;
    let mut ids = Ids::new(ids_args).await.expect("failed to create ids");

    let ids_output = ids.take_output().expect("No output");

    tokio::spawn(ids_output);

    let ids_alerts = ids.take_alerts().expect("No alerts");

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

    while let Some(ref packets) = packets_iter.next() {
        packets_sent += ids.send(packets).expect("Failed to send packets");
        std::thread::sleep(std::time::Duration::from_millis(10));
        info!("Sent {} packets", packets_sent);

        if packets_sent >= nb_packets {
            break;
        }
    }

    info!("Packets sent, closing connection");
    ids.close()?;

    let alerts: Result<Vec<_>, Error> = ids_alerts.try_collect().await;
    let alerts: Result<Vec<_>, Error> = alerts?.into_iter().flat_map(|v| v).collect();
    let alerts = alerts?;

    info!("Finished collecting alerts");

    Ok((packets_sent, alerts))
}

fn bench_ids_process_4sics(c: &mut Criterion) {
    let benchmark = criterion::Benchmark::new("ids", |b| {
        let _ = env_logger::try_init();

        let rt = tokio::runtime::Runtime::new().expect("Could not create runtime");

        let cargo_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let pcap_path = cargo_dir
            .join("resources")
            .join("4SICS-GeekLounge-151020.pcap");

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
