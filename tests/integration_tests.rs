#![deny(unused_must_use, unused_imports, bare_trait_objects)]
use futures::{FutureExt, StreamExt};
use log::*;
use packet_ipc::server::ConnectedIpc;
use std::convert::TryFrom;
use std::fs::File;
use std::future::Future;
use std::io::Read;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::{Duration, Instant, SystemTime};
use bellini::Config as SuricataConfig;
use bellini::Error;
use bellini::{IntelCache, Tracer};
use bellini::intel::IdsKey;

const SURICATA_YAML: &'static str = "suricata.yaml";
const CUSTOM_RULES: &'static str = "custom.rules";
const ALERT_SOCKET: &'static str = "suricata.alerts";

struct Rule {
    key: IdsKey,
    rule: String,
}

fn parse_rules() -> Result<Rule, Error> {
    let rules_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("resources")
        .join("test.rules");
    let mut f = File::open(rules_path).map_err(Error::Io)?;
    f.read_lines().flat_map(|l| {
        
    })
}

struct WrapperPacket<'a> {
    inner: &'a net_parser_rs::PcapRecord<'a>,
}

impl<'a> WrapperPacket<'a> {
    pub fn new(inner: &'a net_parser_rs::PcapRecord<'a>) -> WrapperPacket {
        WrapperPacket { inner }
    }
}

impl<'a> suricata_rs::ipc::AsIpcPacket for WrapperPacket<'a> {
    fn timestamp(&self) -> &std::time::SystemTime {
        &self.inner.timestamp
    }
    fn data(&self) -> &[u8] {
        self.inner.payload
    }
}

trait TestRunner {
    fn run<'a>(
        &'a mut self,
        ids: &'a Ids,
        ipc_server: &'a mut ConnectedIpc,
    ) -> Pin<Box<dyn Future<Output = usize> + 'a + Send>>;
}

struct TracerTestRunner;

impl TestRunner for TracerTestRunner {
    fn run<'a>(
        &'a mut self,
        _ids: &'a Ids,
        ipc_server: &'a mut ConnectedIpc,
    ) -> Pin<Box<dyn Future<Output = usize> + 'a + Send>> {
        send_tracer(ipc_server, SystemTime::now()).boxed()
    }
}

struct MultiTracerTestRunner;

impl TestRunner for MultiTracerTestRunner {
    fn run<'a>(
        &'a mut self,
        _ids: &'a Ids,
        ipc_server: &'a mut ConnectedIpc,
    ) -> Pin<Box<dyn Future<Output = usize> + 'a + Send>> {
        send_tracers(ipc_server).boxed()
    }
}

async fn send_tracers<'a>(ipc_server: &'a mut ConnectedIpc) -> usize {
    let now = SystemTime::now();
    send_tracer(ipc_server, now - Duration::from_secs(600)).await;
    tokio::timer::delay(Instant::now() + Duration::from_secs(1)).await;
    send_tracer(ipc_server, now - Duration::from_secs(300)).await;
    tokio::timer::delay(Instant::now() + Duration::from_secs(1)).await;
    send_tracer(ipc_server, now).await;
    3
}

struct MultiTracerReloadTestRunner;

impl TestRunner for MultiTracerReloadTestRunner {
    fn run<'a>(
        &'a mut self,
        ids: &'a Ids,
        ipc_server: &'a mut ConnectedIpc,
    ) -> Pin<Box<dyn Future<Output = usize> + 'a + Send>> {
        send_tracers_with_reload(ids, ipc_server).boxed()
    }
}

async fn send_tracers_with_reload<'a>(ids: &'a Ids, ipc_server: &'a mut ConnectedIpc) -> usize {
    let now = SystemTime::now();
    send_tracer(ipc_server, now - Duration::from_secs(600)).await;
    tokio::timer::delay(Instant::now() + Duration::from_secs(1)).await;
    assert!(ids.reload_rules());
    send_tracer(ipc_server, now - Duration::from_secs(300)).await;
    tokio::timer::delay(Instant::now() + Duration::from_secs(1)).await;
    send_tracer(ipc_server, now).await;
    3
}

async fn send_tracer<'a>(ipc_server: &'a mut ConnectedIpc, ts: SystemTime) -> usize {
    let data = Tracer::data().to_vec();
    let p = net_parser_rs::PcapRecord::new(ts, data.len() as _, data.len() as _, &data);
    let ipc_packet =
        suricata_rs::ipc::try_from(&WrapperPacket::new(&p)).expect("Failed to convert");
    ipc_server.send(vec![ipc_packet]).expect("Failed to send");

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

impl TestRunner for PcapPathTestRunner {
    fn run<'a>(
        &'a mut self,
        _ids: &'a Ids,
        ipc_server: &'a mut ConnectedIpc,
    ) -> Pin<Box<dyn Future<Output = usize> + 'a + Send>> {
        let (_, f) = net_parser_rs::CaptureFile::parse(self.pcap_bytes()).expect("Failed to parse");
        send_packets_from_file(f.records, ipc_server).boxed()
    }
}

async fn send_packets_from_file<'a>(
    records: net_parser_rs::PcapRecords<'a>,
    ipc_server: &'a mut ConnectedIpc,
) -> usize {
    let mut packets_sent = 0;

    info!("Sending packets to ids");

    let records = records.into_inner();
    let mut packets = records.chunks(100).map(|r| {
        r.iter()
            .map(|record| WrapperPacket::new(record))
            .collect::<Vec<_>>()
    });
    let mut packets_to_send = vec![];

    while let Some(mut packets) = packets.next() {
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
        }
    }

    if !packets_to_send.is_empty() {
        let packets = std::mem::replace(&mut packets_to_send, vec![]);
        packets_sent += packets.len();
        ipc_server.send(packets).expect("Failed to send");
    }

    packets_sent
}

async fn run_ids<'a, T: TestRunner>(runner: T) -> Result<(usize, Vec<Vec<u8>>), Error> {
    let mut runner = runner;

    let cargo_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resources_path = cargo_dir.join("resources");

    let temp_file = tempfile::tempdir()
        .expect("Failed to create temp file")
        .into_path();

    let mut file = File::open(resources_path.join("s3.js")).expect("Failed to open rules file");
    let mut rule_bytes = vec![];
    file.read_to_end(&mut rule_bytes)
        .expect("Failed to read rules file");

    let rules: Vec<Rule> = Rule::try_from_slice(&rule_bytes)?;
    let sensor_rules = SensorRules {
        rules: rules,
        etag: vec![],
    };
    let cache: IntelCache = sensor_rules.into();
    let rules = temp_file.join(CUSTOM_RULES);
    cache.materialize_rules(rules.clone())?;

    let alert_path = temp_file.join(ALERT_SOCKET);
    let suricata_yaml = temp_file.join(SURICATA_YAML);

    let mut ids_args = SuricataConfig::default();
    ids_args.materialize_config_to = suricata_yaml;
    ids_args.alert_path = alert_path;
    ids_args.rule_path = rules;
    ids_args.enable_stats = false;
    let mut ids = Ids::new(ids_args).await?;

    let ids_output = ids.take_output().expect("No output");

    tokio::spawn(ids_output);

    let ids_alerts = ids.take_alerts().expect("No alerts");
    let mut ipc_server = ids.take_ipc_server().expect("No ipc server");

    let packets_sent = runner.run(&ids, &mut ipc_server).await;

    info!("Packets sent, closing connection");

    let mut ipc_pin = Pin::new(&mut ipc_server);
    ipc_pin.close().map_err(Error::PacketIpc)?;

    std::thread::sleep(std::time::Duration::from_secs(5));

    let alerts: Vec<Result<Vec<_>, Error>> = ids_alerts.collect().await;
    let alerts: Result<Vec<_>, Error> = alerts.into_iter().collect();
    let alerts: Vec<_> = alerts?.into_iter().flatten().collect();

    info!("Finished collecting alerts");

    Ok((packets_sent, alerts))
}

fn pcaps_available() -> bool {
    let pcap_sync = std::env::var("ENABLE_PCAP_SYNC").unwrap_or("0".to_owned());
    pcap_sync == "1".to_ascii_lowercase()
}

#[tokio::test]
async fn ids_process_canary() {
    let _ = env_logger::try_init();

    if pcaps_available() {
        let pcap_path = pcaps::get_pcap_path("canary.pcap");

        let runner = PcapPathTestRunner::new(pcap_path);

        let (packets_sent, alerts) = run_ids(runner).await.expect("Failed to run");

        let alerts_len = alerts.len();

        for alert in alerts {
            info!(
                "Alert={}",
                String::from_utf8(alert.clone()).expect("Failed to convert to string")
            );
            let eve = suricata_rs::eve::Message::try_from(alert.as_ref())
                .expect("Failed to convert alert");
            assert_eq!(
                eve.src_ip,
                "10.151.223.136"
                    .parse::<std::net::IpAddr>()
                    .expect("Failed to parse")
            );
            assert_eq!(
                eve.dest_ip,
                "203.0.113.99"
                    .parse::<std::net::IpAddr>()
                    .expect("Failed to parse")
            );
            assert_eq!(eve.alert.signature_id, 600074);
        }

        assert_eq!(packets_sent, 10);
        assert_eq!(alerts_len, 1);
    } else {
        warn!("Skipping ids_process_canary since pcaps are not available. Enable with environment variable `ENABLE_PCAP_SYNC=1`.");
    }
}

#[tokio::test]
async fn ids_process_tracer() {
    let _ = env_logger::try_init();

    let runner = TracerTestRunner;

    let (packets_sent, alerts) = run_ids(runner).await.expect("Failed to run");

    let alerts_len = alerts.len();

    for alert in alerts {
        info!(
            "Alert={}",
            String::from_utf8(alert.clone()).expect("Failed to convert to string")
        );
        let eve =
            suricata_rs::eve::Message::try_from(alert.as_ref()).expect("Failed to convert alert");
        assert_eq!(
            eve.src_ip,
            "10.1.10.39"
                .parse::<std::net::IpAddr>()
                .expect("Failed to parse")
        );
        assert_eq!(
            eve.dest_ip,
            "75.75.75.75"
                .parse::<std::net::IpAddr>()
                .expect("Failed to parse")
        );
        assert_eq!(eve.alert.signature_id, Tracer::key().sid);
    }

    assert_eq!(packets_sent, 1);
    assert_eq!(alerts_len, 1);
}

#[tokio::test]
async fn ids_process_tracer_multiple() {
    let _ = env_logger::try_init();

    let runner = MultiTracerTestRunner;

    let (packets_sent, alerts) = run_ids(runner).await.expect("Failed to run");

    let alerts_len = alerts.len();

    for alert in alerts {
        info!(
            "Alert={}",
            String::from_utf8(alert.clone()).expect("Failed to convert to string")
        );
        let eve =
            suricata_rs::eve::Message::try_from(alert.as_ref()).expect("Failed to convert alert");
        assert_eq!(
            eve.src_ip,
            "10.1.10.39"
                .parse::<std::net::IpAddr>()
                .expect("Failed to parse")
        );
        assert_eq!(
            eve.dest_ip,
            "75.75.75.75"
                .parse::<std::net::IpAddr>()
                .expect("Failed to parse")
        );
        assert_eq!(eve.alert.signature_id, Tracer::key().sid);
    }

    assert_eq!(packets_sent, 3);
    assert_eq!(alerts_len, 3);
}

#[tokio::test]
async fn ids_process_tracer_multiple_reload() {
    let _ = env_logger::try_init();

    let runner = MultiTracerReloadTestRunner;

    let (packets_sent, alerts) = run_ids(runner).await.expect("Failed to run");

    let alerts_len = alerts.len();

    for alert in alerts {
        info!(
            "Alert={}",
            String::from_utf8(alert.clone()).expect("Failed to convert to string")
        );
        let eve =
            suricata_rs::eve::Message::try_from(alert.as_ref()).expect("Failed to convert alert");
        assert_eq!(
            eve.src_ip,
            "10.1.10.39"
                .parse::<std::net::IpAddr>()
                .expect("Failed to parse")
        );
        assert_eq!(
            eve.dest_ip,
            "75.75.75.75"
                .parse::<std::net::IpAddr>()
                .expect("Failed to parse")
        );
        assert_eq!(eve.alert.signature_id, Tracer::key().sid);
    }

    assert_eq!(packets_sent, 3);
    assert_eq!(alerts_len, 3);
}

#[tokio::test]
async fn ids_process_4sics() {
    let _ = env_logger::try_init();

    if pcaps_available() {
        let pcap_path = pcaps::get_pcap_path("4SICS-GeekLounge-151020.pcap");

        let runner = PcapPathTestRunner::new(pcap_path);

        let (packets_sent, alerts) = run_ids(runner).await.expect("Failed to run");

        assert_eq!(packets_sent, 246137);
        assert_eq!(alerts.len(), 0);
    } else {
        warn!("Skipping ids_process_4sics since pcaps are not available. Enable with environment variable `ENABLE_PCAP_SYNC=1`.")
    }
}
