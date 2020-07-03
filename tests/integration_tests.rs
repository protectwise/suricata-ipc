#![deny(unused_must_use, unused_imports, bare_trait_objects)]
use async_trait::async_trait;
use futures::StreamExt;
use log::*;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
#[cfg(feature = "protobuf")]
use suricata_ipc::prelude::proto::Eve;
use suricata_ipc::prelude::*;
use suricata_ipc::PacketSender;

const SURICATA_YAML: &'static str = "suricata.yaml";
const CUSTOM_RULES: &'static str = "custom.rules";
const ALERT_SOCKET: &'static str = "suricata.alerts";

fn prepare_executor() {
    for _ in 0..5 {
        // A pending future is one that simply yields forever.
        std::thread::spawn(|| smol::run(futures::future::pending::<()>()));
    }
}

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

struct TestResult<T> {
    packets_sent: usize,
    messages: Vec<T>,
    intel_cache: IntelCache<Rule>,
}

#[async_trait]
trait TestRunner {
    async fn run<'a, T>(&'a mut self, ids: &'a Ids<'a, T>, sender: &'a PacketSender<'a>) -> usize;
    fn senders(&self) -> usize;
}

struct TracerTestRunner;

#[async_trait]
impl TestRunner for TracerTestRunner {
    async fn run<'a, T>(&'a mut self, ids: &'a Ids<'a, T>, sender: &'a PacketSender<'a>) -> usize {
        send_tracer(ids, sender, SystemTime::now()).await
    }
    fn senders(&self) -> usize {
        1
    }
}

struct MultiTracerTestRunner;

#[async_trait]
impl TestRunner for MultiTracerTestRunner {
    async fn run<'a, T>(&'a mut self, ids: &'a Ids<'a, T>, sender: &'a PacketSender<'a>) -> usize {
        send_tracers(ids, sender).await
    }
    fn senders(&self) -> usize {
        1
    }
}

async fn send_tracers<'a, T>(ids: &'a Ids<'a, T>, sender: &'a PacketSender<'a>) -> usize {
    let now = SystemTime::now();
    send_tracer(ids, sender, now - Duration::from_secs(600)).await;
    smol::Timer::after(Duration::from_secs(1)).await;
    send_tracer(ids, sender, now - Duration::from_secs(300)).await;
    smol::Timer::after(Duration::from_secs(1)).await;
    send_tracer(ids, sender, now).await;
    3
}

struct MultiTracerReloadTestRunner;

#[async_trait]
impl TestRunner for MultiTracerReloadTestRunner {
    async fn run<'a, T>(&'a mut self, ids: &'a Ids<'a, T>, sender: &'a PacketSender<'a>) -> usize {
        send_tracers_with_reload(ids, sender).await
    }
    fn senders(&self) -> usize {
        1
    }
}

async fn send_tracers_with_reload<'a, T>(
    ids: &'a Ids<'a, T>,
    sender: &'a PacketSender<'a>,
) -> usize {
    let now = SystemTime::now();
    send_tracer(ids, sender, now - Duration::from_secs(600)).await;
    smol::Timer::after(Duration::from_secs(1)).await;
    assert!(ids.reload_rules());
    send_tracer(ids, sender, now - Duration::from_secs(300)).await;
    smol::Timer::after(Duration::from_secs(1)).await;
    send_tracer(ids, sender, now).await;
    3
}

async fn send_tracer<'a, T>(
    _ids: &'a Ids<'a, T>,
    sender: &'a PacketSender<'a>,
    ts: SystemTime,
) -> usize {
    let data = Tracer::data().to_vec();
    let p = net_parser_rs::PcapRecord::new(ts, data.len() as _, data.len() as _, &data);
    sender
        .send(&[WrapperPacket::new(&p)])
        .expect("Failed to send");

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
    async fn run<'a, T>(&'a mut self, ids: &'a Ids<'a, T>, sender: &'a PacketSender<'a>) -> usize {
        let (_, f) = net_parser_rs::CaptureFile::parse(self.pcap_bytes()).expect("Failed to parse");
        send_packets_from_file(f.records, ids, sender).await
    }
    fn senders(&self) -> usize {
        1
    }
}

async fn send_packets_from_file<'a, T>(
    records: net_parser_rs::PcapRecords<'a>,
    _ids: &'a Ids<'a, T>,
    sender: &'a PacketSender<'a>,
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
        packets_sent += sender
            .send(packets.as_slice())
            .expect("Failed to send packets");
        smol::Timer::after(Duration::from_millis(10)).await;
        trace!("Sent {} packets", packets_sent);
    }

    packets_sent
}

struct PcapPathTestRunnerMulti {
    pcap_bytes: Vec<u8>,
}

impl PcapPathTestRunnerMulti {
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
impl TestRunner for PcapPathTestRunnerMulti {
    async fn run<'a, T>(&'a mut self, ids: &'a Ids<'a, T>, sender: &'a PacketSender<'a>) -> usize {
        let (_, f) = net_parser_rs::CaptureFile::parse(self.pcap_bytes()).expect("Failed to parse");
        send_packets_from_file(f.records, ids, sender).await
    }
    fn senders(&self) -> usize {
        2
    }
}

async fn run_ids<'a, M, T>(runner: T) -> Result<TestResult<M>, Error>
where
    T: TestRunner,
    M: for<'de> serde::Deserialize<'de>,
{
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
    ids_args.connections = runner.senders();
    ids_args.materialize_config_to = suricata_yaml;
    ids_args.alerts = AlertConfiguration::uds(alert_path);
    ids_args.rule_path = rules;
    ids_args.exe_path =
        PathBuf::from(std::env::var("SURICATA_EXE").unwrap_or("/usr/bin/suricata".to_owned()));
    ids_args.suriata_config_path =
        PathBuf::from(std::env::var("SURICATA_CONFIG_DIR").unwrap_or("/etc/suricata".to_owned()));
    let mut ids: Ids<M> = Ids::new(ids_args).await?;

    let mut ids_messages = ids.take_messages().expect("No alerts");

    let mut sender = ids.take_sender().unwrap();
    let packets_sent = runner.run(&ids, &sender).await;

    smol::Timer::after(std::time::Duration::from_secs(1)).await;

    info!("Packets sent, closing connection");
    sender.close()?;

    smol::Timer::after(std::time::Duration::from_secs(1)).await;

    let mut messages = vec![];
    loop {
        if let Some(try_m) = ids_messages.next().await {
            messages.extend(try_m?);
        } else {
            break;
        }
    }

    info!("Finished collecting alerts");

    Ok(TestResult {
        packets_sent: packets_sent,
        messages: messages,
        intel_cache: cache,
    })
}

#[test]
fn ids_process_testmyids() {
    let _ = env_logger::try_init();

    prepare_executor();

    let cargo_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let pcap_path = cargo_dir.join("resources").join("testmyids.pcap");

    let runner = PcapPathTestRunner::new(pcap_path);

    let result: TestResult<suricata_ipc::prelude::EveMessage> =
        smol::block_on(run_ids(runner)).expect("Failed to run");

    let mut alerts = 0;

    for eve in result.messages {
        if let EveEventType::Alert(ref alert) = eve.event {
            alerts += 1;
            assert_eq!(
                alert.event_fields.src_ip,
                "82.165.177.154"
                    .parse::<std::net::IpAddr>()
                    .expect("Failed to parse")
            );
            assert_eq!(
                alert.event_fields.dest_ip,
                "10.16.1.11"
                    .parse::<std::net::IpAddr>()
                    .expect("Failed to parse")
            );
            assert_eq!(alert.info.signature_id, 2100498);
            assert!(result.intel_cache.observed(eve).is_some());
        }
    }

    assert_eq!(result.packets_sent, 10);
    assert_eq!(alerts, 1);
}

#[test]
fn ids_process_testmyids_multi() {
    let _ = env_logger::try_init();

    prepare_executor();

    let cargo_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let pcap_path = cargo_dir.join("resources").join("testmyids.pcap");

    let runner = PcapPathTestRunnerMulti::new(pcap_path);

    let result: TestResult<suricata_ipc::prelude::EveMessage> =
        smol::block_on(run_ids(runner)).expect("Failed to run");

    let mut alerts = 0;

    for eve in result.messages {
        if let EveEventType::Alert(ref alert) = eve.event {
            alerts += 1;
            assert_eq!(
                alert.event_fields.src_ip,
                "82.165.177.154"
                    .parse::<std::net::IpAddr>()
                    .expect("Failed to parse")
            );
            assert_eq!(
                alert.event_fields.dest_ip,
                "10.16.1.11"
                    .parse::<std::net::IpAddr>()
                    .expect("Failed to parse")
            );
            assert_eq!(alert.info.signature_id, 2100498);
            assert!(result.intel_cache.observed(eve).is_some());
        }
    }

    assert_eq!(result.packets_sent, 10);
    assert_eq!(alerts, 1);
}

#[test]
fn ids_process_tracer() {
    let _ = env_logger::try_init();

    prepare_executor();

    let runner = TracerTestRunner;

    let result: TestResult<suricata_ipc::prelude::EveMessage> =
        smol::block_on(run_ids(runner)).expect("Failed to run");

    let mut alerts = 0;

    for eve in result.messages {
        if let EveEventType::Alert(ref alert) = eve.event {
            alerts += 1;
            assert_eq!(
                alert.event_fields.src_ip,
                "10.1.10.39"
                    .parse::<std::net::IpAddr>()
                    .expect("Failed to parse")
            );
            assert_eq!(
                alert.event_fields.dest_ip,
                "75.75.75.75"
                    .parse::<std::net::IpAddr>()
                    .expect("Failed to parse")
            );
            assert_eq!(alert.info.signature_id, Tracer::key().sid);
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

#[test]
fn ids_process_tracer_multiple() {
    let _ = env_logger::try_init();

    prepare_executor();

    let runner = MultiTracerTestRunner;

    let result: TestResult<suricata_ipc::prelude::EveMessage> =
        smol::block_on(run_ids(runner)).expect("Failed to run");

    let mut alerts = 0;

    for eve in result.messages {
        debug!("Received {:?}", eve);
        if let EveEventType::Alert(ref alert) = eve.event {
            alerts += 1;
            assert_eq!(
                alert.event_fields.src_ip,
                "10.1.10.39"
                    .parse::<std::net::IpAddr>()
                    .expect("Failed to parse")
            );
            assert_eq!(
                alert.event_fields.dest_ip,
                "75.75.75.75"
                    .parse::<std::net::IpAddr>()
                    .expect("Failed to parse")
            );
            assert_eq!(alert.info.signature_id, Tracer::key().sid);
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

#[test]
fn ids_process_tracer_multiple_reload() {
    let _ = env_logger::try_init();

    prepare_executor();

    let runner = MultiTracerReloadTestRunner;

    let result: TestResult<suricata_ipc::prelude::EveMessage> =
        smol::block_on(run_ids(runner)).expect("Failed to run");

    let mut alerts = 0;

    for eve in result.messages {
        if let EveEventType::Alert(ref alert) = eve.event {
            alerts += 1;
            assert_eq!(
                alert.event_fields.src_ip,
                "10.1.10.39"
                    .parse::<std::net::IpAddr>()
                    .expect("Failed to parse")
            );
            assert_eq!(
                alert.event_fields.dest_ip,
                "75.75.75.75"
                    .parse::<std::net::IpAddr>()
                    .expect("Failed to parse")
            );
            assert_eq!(alert.info.signature_id, Tracer::key().sid);
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

#[test]
fn ids_process_4sics() {
    let _ = env_logger::try_init();

    prepare_executor();

    let cargo_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let pcap_path = cargo_dir
        .join("resources")
        .join("4SICS-GeekLounge-151020.pcap");

    let runner = PcapPathTestRunner::new(pcap_path);

    let result: TestResult<suricata_ipc::prelude::EveMessage> =
        smol::block_on(run_ids(runner)).expect("Failed to run");

    assert_eq!(result.packets_sent, 246_137);

    let mut alerts = 0;
    let mut dns = 0;
    let mut flows = 0;
    let mut http = 0;
    let mut smtp = 0;
    let mut tls = 0;
    let mut stats_messages = 0;
    let mut packets = 0;

    for msg in result.messages {
        match msg.event {
            EveEventType::Alert(a) => {
                assert!(a.event_fields.community_id.is_some());
                alerts += 1;
            }
            EveEventType::Dns(_) => {
                dns += 1;
            }
            EveEventType::Flow(f) => {
                assert!(f.event_fields.community_id.is_some());
                flows += 1;
            }
            EveEventType::Http(_) => {
                http += 1;
            }
            EveEventType::Smtp(_) => {
                smtp += 1;
            }
            EveEventType::Stats(stats) => {
                packets = stats.info.decoder.pkts;
                stats_messages += 1;
            }
            EveEventType::Tls(_) => {
                tls += 1;
            }
        }
    }

    assert_eq!(alerts, 0);
    assert!(dns > 27_000);
    assert_eq!(http, 0);
    assert!(flows > 9_000);
    assert_eq!(smtp, 0);
    assert!(stats_messages > 1);
    assert_eq!(tls, 0);
    assert_eq!(packets, 246_137);
}

#[cfg(feature = "protobuf")]
#[test]
fn ids_process_tracer_proto() {
    let _ = env_logger::try_init();

    prepare_executor();

    let runner = TracerTestRunner;

    let result: TestResult<Eve> = smol::block_on(run_ids(runner)).expect("Failed to run");

    let mut alerts = 0;

    for eve in result.messages {
        if let Some(alert) = &eve.alert {
            alerts += 1;
            assert_eq!(eve.src_ip.as_ref().unwrap(), "10.1.10.39");
            assert_eq!(eve.dest_ip.as_ref().unwrap(), "75.75.75.75");
            assert_eq!(alert.signature_id as u64, Tracer::key().sid);
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

#[cfg(feature = "protobuf")]
#[test]
fn ids_process_4sics_proto() {
    let _ = env_logger::try_init();

    prepare_executor();

    let cargo_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let pcap_path = cargo_dir
        .join("resources")
        .join("4SICS-GeekLounge-151020.pcap");

    let runner = PcapPathTestRunner::new(pcap_path);

    let result: TestResult<Eve> = smol::block_on(run_ids(runner)).expect("Failed to run");

    assert_eq!(result.packets_sent, 246_137);

    let mut alerts = 0;
    let mut flows = 0;
    let mut stats_messages = 0;
    let mut packets = 0;

    for msg in result.messages {
        if let Some(_) = &msg.flow {
            flows += 1;
        }
        if let Some(_) = &msg.alert {
            alerts += 1;
        }
        if let Some(d) = &msg.stats_decoder {
            packets = d.pkts;
            stats_messages += 1;
        }
    }

    assert_eq!(alerts, 0);
    assert!(flows > 10_000);
    assert!(stats_messages > 1);
    assert_eq!(packets, 246_137);
}
