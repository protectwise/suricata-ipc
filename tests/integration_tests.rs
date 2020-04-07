#![deny(unused_must_use, unused_imports, bare_trait_objects)]
use async_trait::async_trait;
use futures::TryStreamExt;
use log::*;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use suricata_ipc::prelude::*;

const SURICATA_YAML: &'static str = "suricata.yaml";
const CUSTOM_RULES: &'static str = "custom.rules";
const ALERT_SOCKET: &'static str = "suricata.alerts";

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

struct TestResult {
    packets_sent: usize,
    messages: Vec<EveMessage>,
    intel_cache: IntelCache<Rule>,
}

#[async_trait]
trait TestRunner {
    async fn run<'a>(&'a mut self, ids: &'a Ids<'a>) -> usize;
}

struct TracerTestRunner;

#[async_trait]
impl TestRunner for TracerTestRunner {
    async fn run<'a>(&'a mut self, ids: &'a Ids<'a>) -> usize {
        send_tracer(ids, SystemTime::now()).await
    }
}

struct MultiTracerTestRunner;

#[async_trait]
impl TestRunner for MultiTracerTestRunner {
    async fn run<'a>(&'a mut self, ids: &'a Ids<'a>) -> usize {
        send_tracers(ids).await
    }
}

async fn send_tracers<'a>(ids: &'a Ids<'a>) -> usize {
    let now = SystemTime::now();
    send_tracer(ids, now - Duration::from_secs(600)).await;
    tokio::time::delay_for(Duration::from_secs(1)).await;
    send_tracer(ids, now - Duration::from_secs(300)).await;
    tokio::time::delay_for(Duration::from_secs(1)).await;
    send_tracer(ids, now).await;
    3
}

struct MultiTracerReloadTestRunner;

#[async_trait]
impl TestRunner for MultiTracerReloadTestRunner {
    async fn run<'a>(&'a mut self, ids: &'a Ids<'a>) -> usize {
        send_tracers_with_reload(ids).await
    }
}

async fn send_tracers_with_reload<'a>(ids: &'a Ids<'a>) -> usize {
    let now = SystemTime::now();
    send_tracer(ids, now - Duration::from_secs(600)).await;
    tokio::time::delay_for(Duration::from_secs(1)).await;
    assert!(ids.reload_rules());
    send_tracer(ids, now - Duration::from_secs(300)).await;
    tokio::time::delay_for(Duration::from_secs(1)).await;
    send_tracer(ids, now).await;
    3
}

async fn send_tracer<'a>(ids: &'a Ids<'a>, ts: SystemTime) -> usize {
    let data = Tracer::data().to_vec();
    let p = net_parser_rs::PcapRecord::new(ts, data.len() as _, data.len() as _, &data);
    ids.send(&[WrapperPacket::new(&p)]).expect("Failed to send");

    1
}

struct PcapPathTestRunner {
    pcap_bytes: Vec<u8>,
}

impl PcapPathTestRunner {
    pub fn new(pcap_path: PathBuf) -> PcapPathTestRunner {
        let mut f = File::open(pcap_path).expect("Could not open file");
        let mut pcap_bytes = vec![];
        f.read_to_end(&mut pcap_bytes).expect("Failed to read file");
        PcapPathTestRunner {
            pcap_bytes: pcap_bytes,
        }
    }

    pub fn pcap_bytes(&self) -> &[u8] {
        &self.pcap_bytes
    }
}

#[async_trait]
impl TestRunner for PcapPathTestRunner {
    async fn run<'a>(&'a mut self, ids: &'a Ids<'a>) -> usize {
        let (_, f) = net_parser_rs::CaptureFile::parse(self.pcap_bytes()).expect("Failed to parse");
        send_packets_from_file(f.records, ids).await
    }
}

async fn send_packets_from_file<'a>(
    records: net_parser_rs::PcapRecords<'a>,
    ids: &'a Ids<'a>,
) -> usize {
    let mut packets_sent = 0;

    info!("Sending packets to ids");

    let records = records.into_inner();
    let mut packets = records.chunks(100).map(|r| {
        r.iter()
            .map(|record| WrapperPacket::new(record))
            .collect::<Vec<_>>()
    });

    while let Some(ref packets) = packets.next() {
        packets_sent += ids
            .send(packets.as_slice())
            .expect("Failed to send packets");
        tokio::time::delay_for(Duration::from_millis(10)).await;
        trace!("Sent {} packets", packets_sent);
    }

    packets_sent
}

async fn run_ids<'a, T: TestRunner>(runner: T) -> Result<TestResult, Error> {
    let mut runner = runner;

    let cargo_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resources_path = cargo_dir.join("resources");

    let temp_file = tempfile::tempdir()
        .expect("Failed to create temp file")
        .into_path();

    let rules = Rules::from_path(resources_path.join("test.rules")).expect("Failed to read rules");
    let cache: IntelCache<_> = rules.into();
    let rules = temp_file.join(CUSTOM_RULES);
    cache.materialize_rules(rules.clone())?;

    let alert_path = temp_file.join(ALERT_SOCKET);
    let suricata_yaml = temp_file.join(SURICATA_YAML);

    let mut ids_args = Config::default();
    ids_args.materialize_config_to = suricata_yaml;
    ids_args.alert_path = alert_path;
    ids_args.rule_path = rules;
    ids_args.exe_path =
        PathBuf::from(std::env::var("SURICATA_EXE_PATH").unwrap_or("/usr/bin/suricata".to_owned()));
    ids_args.suriata_config_path =
        PathBuf::from(std::env::var("SURICATA_CONFIG_PATH").unwrap_or("/etc/suricata".to_owned()));
    let mut ids = Ids::new(ids_args).await?;

    let ids_output = ids.take_output().expect("No output");

    tokio::spawn(ids_output);

    let ids_messages = ids.take_messages().expect("No alerts");

    let packets_sent = runner.run(&mut ids).await;

    tokio::time::delay_for(std::time::Duration::from_secs(1)).await;

    info!("Packets sent, closing connection");
    ids.close()?;

    tokio::time::delay_for(std::time::Duration::from_secs(1)).await;

    let messages: Result<Vec<_>, Error> = ids_messages.try_collect().await;
    let messages: Result<Vec<_>, Error> = messages?.into_iter().flat_map(|v| v).collect();
    let messages = messages?;

    info!("Finished collecting alerts");

    Ok(TestResult {
        packets_sent: packets_sent,
        messages: messages,
        intel_cache: cache,
    })
}

#[tokio::test]
async fn ids_process_testmyids() {
    let _ = env_logger::try_init();

    let cargo_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let pcap_path = cargo_dir.join("resources").join("testmyids.pcap");

    let runner = PcapPathTestRunner::new(pcap_path);

    let result = run_ids(runner).await.expect("Failed to run");

    let mut alerts = 0;

    for eve in result.messages {
        if let EveEventType::Alert(ref alert) = eve.event {
            alerts += 1;
            assert_eq!(
                alert.src_ip,
                "82.165.177.154"
                    .parse::<std::net::IpAddr>()
                    .expect("Failed to parse")
            );
            assert_eq!(
                alert.dest_ip,
                "10.16.1.11"
                    .parse::<std::net::IpAddr>()
                    .expect("Failed to parse")
            );
            assert_eq!(alert.alert.signature_id, 2100498);
            assert!(result.intel_cache.observed(eve).is_some());
        }
    }

    assert_eq!(result.packets_sent, 10);
    assert_eq!(alerts, 1);
}

#[tokio::test]
async fn ids_process_tracer() {
    let _ = env_logger::try_init();

    let runner = TracerTestRunner;

    let result = run_ids(runner).await.expect("Failed to run");

    let mut alerts = 0;

    for eve in result.messages {
        if let EveEventType::Alert(ref alert) = eve.event {
            alerts += 1;
            assert_eq!(
                alert.src_ip,
                "10.1.10.39"
                    .parse::<std::net::IpAddr>()
                    .expect("Failed to parse")
            );
            assert_eq!(
                alert.dest_ip,
                "75.75.75.75"
                    .parse::<std::net::IpAddr>()
                    .expect("Failed to parse")
            );
            assert_eq!(alert.alert.signature_id, Tracer::key().sid);
            let observed = result.intel_cache.observed(eve).expect("No intel");
            if let Observed::Tracer(_) = observed {
                //ok
            } else {
                panic!("Alert was not determed to be a tracer");
            }
        }
    }

    assert_eq!(result.packets_sent, 1);
    assert_eq!(alerts, 1);
}

#[tokio::test]
async fn ids_process_tracer_multiple() {
    let _ = env_logger::try_init();

    let runner = MultiTracerTestRunner;

    let result = run_ids(runner).await.expect("Failed to run");

    let mut alerts = 0;

    for eve in result.messages {
        debug!("Received {:?}", eve);
        if let EveEventType::Alert(ref alert) = eve.event {
            alerts += 1;
            assert_eq!(
                alert.src_ip,
                "10.1.10.39"
                    .parse::<std::net::IpAddr>()
                    .expect("Failed to parse")
            );
            assert_eq!(
                alert.dest_ip,
                "75.75.75.75"
                    .parse::<std::net::IpAddr>()
                    .expect("Failed to parse")
            );
            assert_eq!(alert.alert.signature_id, Tracer::key().sid);
            let observed = result.intel_cache.observed(eve).expect("No intel");
            if let Observed::Tracer(_) = observed {
                //ok
            } else {
                panic!("Alert was not determined to be a tracer");
            }
        }
    }

    assert_eq!(result.packets_sent, 3);
    assert_eq!(alerts, 3);
}

#[tokio::test]
async fn ids_process_tracer_multiple_reload() {
    let _ = env_logger::try_init();

    let runner = MultiTracerReloadTestRunner;

    let result = run_ids(runner).await.expect("Failed to run");

    let mut alerts = 0;

    for eve in result.messages {
        if let EveEventType::Alert(ref alert) = eve.event {
            alerts += 1;
            assert_eq!(
                alert.src_ip,
                "10.1.10.39"
                    .parse::<std::net::IpAddr>()
                    .expect("Failed to parse")
            );
            assert_eq!(
                alert.dest_ip,
                "75.75.75.75"
                    .parse::<std::net::IpAddr>()
                    .expect("Failed to parse")
            );
            assert_eq!(alert.alert.signature_id, Tracer::key().sid);
            let observed = result.intel_cache.observed(eve).expect("No intel");
            if let Observed::Tracer(_) = observed {
                //ok
            } else {
                panic!("Alert was not determed to be a tracer");
            }
        }
    }

    assert_eq!(result.packets_sent, 3);
    assert_eq!(alerts, 3);
}

#[tokio::test]
async fn ids_process_4sics() {
    let _ = env_logger::try_init();

    let cargo_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let pcap_path = cargo_dir
        .join("resources")
        .join("4SICS-GeekLounge-151020.pcap");

    let runner = PcapPathTestRunner::new(pcap_path);

    let result = run_ids(runner).await.expect("Failed to run");

    assert_eq!(result.packets_sent, 246_137);

    let mut alerts = 0;
    let mut flows = 0;
    let mut stats_messages = 0;
    let mut packets = 0;

    for msg in result.messages {
        match msg.event {
            EveEventType::Alert(a) => {
                assert!(a.community_id.is_some());
                alerts += 1;
            }
            EveEventType::Stats { stats } => {
                packets = stats.decoder.pkts;
                stats_messages += 1;
            }
            EveEventType::Flow(f) => {
                assert!(f.community_id.is_some());
                flows += 1;
            }
        }
    }

    assert_eq!(alerts, 0);
    assert!(flows > 10_000);
    assert!(stats_messages > 1);
    assert_eq!(packets, 246_137);
}
