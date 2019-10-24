use rdkafka::ClientConfig;
use rdkafka::async_support::*;
use bellini::prelude::EveMessage;

const BELLINI_TOPIC: &'static str = "bellini";

pub struct Producer {
    producer: FutureProducer,
}

#[derive(Debug)]
pub struct ProduceResult {
    pub offset: i64,
    pub partition: i32,
}

impl Producer {
    pub fn new() -> Self {
        let bootstrap_servers = std::env::var("KAFKA_CONNECT")
            .unwrap_or("kafka:9092".to_owned());
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", &bootstrap_servers)
            .set("produce.offset.report", "true")
            .set("message.timeout.ms", "5000")
            .create()
            .expect("Producer creation error");
        Self {
            producer: producer,
        }
    }

    pub async fn produce(&self, message: EveMessage) -> ProduceResult {
        let payload = serde_json::to_string(&message).expect("Failed to serialize");
        let key = format!("{}:{}", message.alert.gid, message.alert.signature_id);
        let record = FutureRecord {
            topic: BELLINI_TOPIC,
            partition: None,
            payload: Some(&payload),
            key: Some(&key),
            timestamp: None,
            headers: None,
        };
        match self.producer.send(record, 100).await {
            Ok(Ok((partition, offset))) => ProduceResult { offset: offset, partition: partition },
            Ok(Err((e, _))) => panic!("Failed to produce record: {:?}", e),
            Err(e) => panic!("Error waiting for produced record: {:?}", e),
        }
    }
}