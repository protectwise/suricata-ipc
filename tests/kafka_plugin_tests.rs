#[cfg(feature = "kafka")]
pub mod tests {
    use futures::StreamExt;
    use rdkafka::consumer::Consumer;
    use smol::channel::unbounded;
    use std::collections::HashMap;
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use suricata_ipc::config::{eve, output, plugin};
    use suricata_ipc::prelude::*;

    fn prepare_executor() {
        std::env::set_var("SMOL_THREADS", "5");
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

    struct KafkaPlugin {
        path: PathBuf,
    }

    impl plugin::Plugin for KafkaPlugin {
        fn name(&self) -> &str {
            "kafka"
        }
        fn path(&self) -> &Path {
            self.path.as_path()
        }
        fn config(&self) -> Option<String> {
            None
        }
    }

    pub struct SmolRuntime;

    impl rdkafka::util::AsyncRuntime for SmolRuntime {
        type Delay = futures::future::Map<smol::Timer, fn(std::time::Instant)>;

        fn spawn<T>(task: T)
        where
            T: std::future::Future<Output = ()> + Send + 'static,
        {
            smol::spawn(task).detach()
        }

        fn delay_for(duration: std::time::Duration) -> Self::Delay {
            smol::Timer::after(duration).map(|_| ())
        }
    }

    #[cfg(feature = "kafka-plugin-tests")]
    #[test]
    fn should_send_output_to_kafka() {
        let cargo_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let resources_path = cargo_dir.join("resources");
        let pcap_path = resources_path.join("testmyids.pcap");

        let mut f = std::fs::File::open(pcap_path).expect("Could not open file");
        let mut pcap_bytes = vec![];
        f.read_to_end(&mut pcap_bytes).expect("Failed to read file");

        let (_, f) =
            net_parser_rs::CaptureFile::parse(pcap_bytes.as_slice()).expect("Failed to parse");

        let temp_file = tempfile::tempdir()
            .expect("Failed to create temp file")
            .into_path();

        let rules =
            Rules::from_path(resources_path.join("test.rules")).expect("Failed to read rules");
        let cache: IntelCache<_> = rules.into();
        let rules = temp_file.join(CUSTOM_RULES);
        cache.materialize_rules(rules.clone())?;

        let suricata_yaml = temp_file.join(SURICATA_YAML);

        let brokers = if let Ok(s) = std::env::var("KAFKA_BROKERS") {
            s
        } else {
            "kafka:9092".to_string()
        };

        let topic = "kafka-plugin-test-topic".to_string();
        let consumer: rdkafka::consumer::StreamConsumer = rdkafka::config::ClientConfig::new()
            .set("bootstrap.servers", &brokers)
            .set("session.timeout.ms", "6000")
            .set("enable.auto.commit", "false")
            .set("auto.offset.reset", "earliest")
            .set("group.id", "kafka-plugin-test")
            .create()
            .unwrap();
        consumer.subscribe(&[&topic]).unwrap();

        let alert_stream =
            consumer.start_with_runtime::<SmolRuntime>(std::time::Duration::from_secs(1), false);

        let mut custom_config: HashMap<String, String> = HashMap::default();
        custom_config.insert("brokers".to_string(), brokers.clone());
        custom_config.insert("topic".to_string(), topic.clone());
        let eve_config = eve::EveConfiguration::Custom(eve::Custom {
            name: "kafka".to_string(),
            options: custom_config,
        });

        let outputs = vec![Box::new(output::Alert::new(eve))];

        let plugin_path = if let Ok(s) = std::env::var("SURICATA_KAFKA_PLUGIN") {
            PathBuf::from(s)
        } else if let Ok(s) = std::env::var("SURICATA_PLUGIN_DIR") {
            PathBuf::from(s).join("kafka-plugin.so")
        } else {
            PathBuf::from("/usr/lib/kafka-plugin.so")
        };

        let plugins = vec![Box::new(KafkaPlugin { path: plugin_path })];

        let mut ids_args = Config::default();
        ids_args.outputs = outputs;
        ids_args.plugins = plugins;
        ids_args.materialize_config_to = suricata_yaml;
        ids_args.rule_path = rules;
        let mut ids: Ids<M> = Ids::new(ids_args).await?;

        let mut packets = f.records.into_inner().chunks(100).map(|r| {
            r.iter()
                .map(|record| WrapperPacket::new(record))
                .collect::<Vec<_>>()
        });

        while let Some(ref packets) = packets.next() {
            packets_sent += ids
                .send(packets.as_slice())
                .expect("Failed to send packets");
            smol::Timer::after(std::time::Duration::from_millis(10)).await;
            trace!("Sent {} packets", packets_sent);
        }

        info!("Packets sent, closing connection");
        ids.close()?;

        info!("Finished collecting alerts");

        let mut packets_sent = 0;

        info!("Sending packets to ids");

        packets_sent
    }
}
